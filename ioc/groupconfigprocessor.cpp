/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 *
 * Author George S. McIntyre <george@level-n.com>, 2023
 *
 */

#include <fstream>
#include <map>
#include <string>

#include <dbChannel.h>

#include <yajl_alloc.h>
#include <yajl_parse.h>

#include <pvxs/log.h>
#include <pvxs/nt.h>

#include "dbentry.h"
#include "groupconfigprocessor.h"
#include "groupdefinition.h"
#include "groupprocessorcontext.h"
#include "iocshcommand.h"
#include "iocsource.h"
#include "utilpvt.h"
#include "yajlcallbackhandler.h"

// include last to avoid clash of #define printf with other headers
#include <epicsStdio.h>

namespace pvxs {
namespace ioc {

DEFINE_LOGGER(_logname, "pvxs.ioc.group.processor");

GroupConfigProcessor::GroupConfigProcessor()
    :config(IOCGroupConfig::instance())
{}

/**
 * Parse group configuration that has been defined in db configuration files.
 * This involves extracting info fields named "Q:Group" from the database configuration
 * and converting them to Group Configuration objects.
 */
void GroupConfigProcessor::loadConfigFromDb() {
    // process info blocks named Q:Group to get group configuration
    DBEntry dbEntry;
    for (long status = dbFirstRecordType(dbEntry); !status; status = dbNextRecordType(dbEntry)) {
        for (status = dbFirstRecord(dbEntry); !status; status = dbNextRecord(dbEntry)) {
            const char* jsonGroupDefinition = infoField(dbEntry, "Q:group");
            if (jsonGroupDefinition != nullptr) {
                auto& dbRecordName(dbEntry->precnode->recordname);
                log_debug_printf(_logname, "%s: info(Q:Group, ...\n", dbRecordName);

                try {
                    parseConfigString(jsonGroupDefinition, dbRecordName);
                    if (!groupProcessingWarnings.empty()) {
                        fprintf(stderr, "%s: warning(s) from info(\"Q:group\", ...\n%s", dbRecordName,
                                groupProcessingWarnings.c_str());
                    }
                } catch (std::exception& e) {
                    fprintf(stderr, "%s: Error parsing info(\"Q:group\", ...\n%s", dbRecordName, e.what());
                }
            }
        }
    }
}

/**
 * Parse group definitions from the collected list of group definition files.
 *
 * Get the list of group files configured on the iocServer and convert them to Group Configuration objects.
 */
void GroupConfigProcessor::loadConfigFiles() {
    // take the list of group files to load
    auto groupConfigFiles(std::move(config.groupConfigFiles));

    // For each file load the configuration file
    for(auto& jfile : groupConfigFiles) {
        auto& groupConfigFileName = jfile.fname;

        std::ostringstream buffer;
        std::string line;
        size_t lineno = 0u;
        while(std::getline(*jfile.jf, line)) {
            lineno++;
            if(jfile.handle) {
                if(auto exp = macDefExpand(line.c_str(), jfile.handle.get())) {
                    try{
                        line = exp;
                    }catch(...){
                        free(exp);
                        throw;
                    }
                    free(exp);
                } else {
                    fprintf(stderr, "Error reading \"%s\" line %zu too long\n",
                            groupConfigFileName.c_str(), lineno);
                    continue;
                }
            }
            buffer<<line<<'\n';
        }

        if(!jfile.jf->eof() || jfile.jf->bad()) {
            fprintf(stderr, "Error reading \"%s\"\n", groupConfigFileName.c_str());
            continue;
        }

        log_debug_printf(_logname, "Process dbGroup file \"%s\"\n", groupConfigFileName.c_str());

        try {
            parseConfigString(buffer.str().c_str());
            if (!groupProcessingWarnings.empty()) {
                fprintf(stderr, "warning(s) from group definition file \"%s\"\n%s\n",
                        groupConfigFileName.c_str(), groupProcessingWarnings.c_str());
            }
        } catch (std::exception& e) {
            throw std::runtime_error(
                        SB() << "Error reading group definition file \"" << groupConfigFileName << "\"\n" << e.what());
        }
    }
}

void GroupConfigProcessor::validateGroups() {
    assert(groupDefinitionMap.empty()); // not yet populated
    auto groups(std::move(groupConfigMap));

    for(auto& git : groups) {
        try {
            auto& group = git.second;

            for(auto& fit : group.fieldConfigMap) {
                auto& field = fit.second;
                switch(field.info.type) {
                case MappingInfo::Scalar:
                case MappingInfo::Plain:
                case MappingInfo::Any:
                case MappingInfo::Meta:
                case MappingInfo::Proc:
                    if(field.channel.empty()) {
                        throw std::runtime_error(SB()<<"field "<<fit.first<<" missing required +channel");
                    }
                    break;
                case MappingInfo::Structure:
                case MappingInfo::Const:
                    if(!field.channel.empty()) {
                        fprintf(stderr, "Warning: %s.%s ignores +channel:\"%s\"\n",
                                git.first.c_str(), fit.first.c_str(), field.channel.c_str());
                        field.channel.clear();
                    }
                    break;
                }
            }

            groupConfigMap.emplace(git.first, std::move(git.second));
        }catch(std::exception& e){
            fprintf(stderr, "Error: ignoring invalid group %s : %s\n", git.first.c_str(), e.what());
        }
    }
}

/**
 * After the group configuration has been read in
 * this function is called to evaluate it and create group definitions
 */
void GroupConfigProcessor::defineGroups() {
    for (auto& groupConfigIterator: groupConfigMap) {
        const std::string& groupName = groupConfigIterator.first;
        const GroupConfig& groupConfig = groupConfigIterator.second;

        try {
            // If the configured group name is the same as a record name then ignore it
            if (dbChannelTest(groupName.c_str()) == 0) {
                fprintf(stderr, "%s : Error: Group name conflicts with record name.  Ignoring...\n",
                        groupName.c_str());
                continue;
            }

            // Create group when it is first referenced
            auto&& groupDefinition = groupDefinitionMap[groupName];

            // If the structure ID is not already set then set it
            if (!groupConfig.structureId.empty()) {
                groupDefinitionMap[groupName].structureId = groupConfig.structureId;
            }

            // configure the group fields
            defineFields(groupDefinition, groupConfig, groupName);

            if (groupConfig.atomicIsSet) {
                defineAtomicity(groupDefinition, groupConfig, groupName);
            }

        } catch (std::exception& e) {
            fprintf(stderr, "Error configuring group \"%s\" : %s\n", groupName.c_str(), e.what());
        }
    }

    // re-sort fields to ensure the shorter names appear first
    defineFieldSortOrder();
}

/**
 * Define the group fields.  Use the given group config to define group's fields
 *
 * @param groupDefinition the group whose fields will be configured
 * @param groupConfig the group configuration to read from
 * @param groupName the name of the group being configured
 * @return reference to the current group
 */
void GroupConfigProcessor::defineFields(GroupDefinition& groupDefinition, const GroupConfig& groupConfig,
                                        const std::string& groupName) {
    for (auto&& fieldConfigMapEntry: groupConfig.fieldConfigMap) {
        const std::string& fieldName = fieldConfigMapEntry.first;
        const FieldConfig& fieldConfig = fieldConfigMapEntry.second;

        if (groupDefinition.fieldMap.count(fieldName)) {
            fprintf(stderr, "%s.%s Warning: ignoring duplicate mapping %s\n",
                    groupName.c_str(), fieldName.c_str(), fieldConfig.channel.c_str());
            continue;
        }

        if(fieldName.empty() && fieldConfig.info.type!=MappingInfo::Meta) {
            fprintf(stderr, "%s.%s Error: only +type:\"meta\" can be mapped at struct top\n",
                    groupName.c_str(), fieldName.c_str());
            continue;
        }

        groupDefinition.fields.emplace_back(fieldConfig, fieldName);
        auto& currentField = groupDefinition.fields.back();

        groupDefinition.fieldMap[fieldName] = (size_t)-1;      // placeholder

        log_debug_printf(_logname, "  pvxs map '%s.%s' <-> '%s'\n",
                         groupName.c_str(),
                         fieldName.c_str(),
                         currentField.channel.c_str());

        defineTriggers(groupDefinition, fieldConfig, fieldName);
    }
}

/*
 * Sort Group fields to ensure putOrder
 */
void GroupConfigProcessor::defineFieldSortOrder() {
    for (auto&& groupDefinitionMapEntry: groupDefinitionMap) {
        auto& groupDefinition = groupDefinitionMapEntry.second;
        std::stable_sort(groupDefinition.fields.begin(), groupDefinition.fields.end(),
                  [](const FieldDefinition& l, const FieldDefinition& r) -> bool
        {
            return l.info.putOrder < r.info.putOrder;
        });
        groupDefinition.fieldMap.clear();

        auto groupFieldIndex = 0;
        for (auto& fieldDefinition: groupDefinition.fields) {
            groupDefinition.fieldMap[fieldDefinition.name] = groupFieldIndex++;
        }
    }
}

/**
 * Configure group atomicity.
 *
 * @param groupDefinition The group definition to update
 * @param groupConfig the source group configuration
 * @param groupName the group's name
 */
void GroupConfigProcessor::defineAtomicity(GroupDefinition& groupDefinition, const GroupConfig& groupConfig,
                                           const std::string& groupName) {
    assert(groupConfig.atomicIsSet);
    TriState atomicity = groupConfig.atomic ? True : False;

    if (groupDefinition.atomic != Unset && groupDefinition.atomic != atomicity) {
        fprintf(stderr, "%s  Warning: pvxs atomic setting inconsistent\n", groupName.c_str());
    }

    groupDefinition.atomic = atomicity;

    log_debug_printf(_logname, "  pvxs atomic '%s' %s\n",
                     groupName.c_str(),
                     groupDefinition.atomic ? "YES" : "NO");
}

/**
 * Load field triggers for a group field.
 *
 * @param groupDefinition The group definition to update
 * @param fieldConfig the field configuration to read trigger configuration from
 * @param fieldName the field name in the group
 */
void GroupConfigProcessor::defineTriggers(GroupDefinition& groupDefinition, const FieldConfig& fieldConfig,
                                          const std::string& fieldName) {
    TriggerNames triggers;
    if (!fieldConfig.trigger.empty()) {
        std::string trigger;
        std::stringstream splitter(fieldConfig.trigger);
        groupDefinition.hasTriggers = true;

        while (std::getline(splitter, trigger, ',')) {
            triggers.insert(std::move(trigger));
        }
    }
    groupDefinition.fieldTriggerMap.emplace(fieldName, std::move(triggers));
}

/**
 * Resolve all trigger references to the fields that they point to. Walk the group definition map,
 * and for each group that has triggers resolve the references, and if it does not have
 * any triggers then set all fields to self reference.
 */
void GroupConfigProcessor::resolveTriggerReferences() {
    // For all groups
    for (auto&& groupDefinitionMapEntry: groupDefinitionMap) {
        auto& groupName = groupDefinitionMapEntry.first;
        auto& groupDefinition = groupDefinitionMapEntry.second;

        // If it has triggers
        if (groupDefinition.hasTriggers) {
            // Configure its triggers
            resolveGroupTriggerReferences(groupDefinition, groupName);
        } else {
            // If no trigger specified for this group then set all fields to trigger themselves
            log_warn_printf(_logname, "Group %s defines no +trigger mappings."
                            "  Default to individual/split monitor updates.\n",
                            groupName.c_str());

            for (auto&& field: groupDefinition.fields) {
                if (!field.channel.empty()) {
                    field.triggerNames.insert(field.name);  // default is self trigger
                }
            }
        }
    }
}

/**
 * Configure a group's triggers.  This involves looping over the map of all triggers and configuring
 * the field triggers that are defined there.
 *
 * @param groupDefinition The group definition to update
 * @param groupName the group name
 */
void
GroupConfigProcessor::resolveGroupTriggerReferences(GroupDefinition& groupDefinition, const std::string& groupName) {
    for (auto&& triggerMapEntry: groupDefinition.fieldTriggerMap) {
        const std::string& fieldName = triggerMapEntry.first;
        const auto& targets = triggerMapEntry.second;

        auto it(groupDefinition.fieldMap.find(fieldName));
        if (it == groupDefinition.fieldMap.end()) {
            fprintf(stderr, "Error: Group \"%s\" defines triggers from nonexistent field \"%s\" \n",
                    groupName.c_str(), fieldName.c_str());
            continue;
        }

        auto index = it->second;
        auto& fieldDefinition = groupDefinition.fields.at(index);

        log_debug_printf(_logname, "  pvxs trigger '%s.%s'  -> ", groupName.c_str(), fieldName.c_str());

        // For all of this trigger's targets
        defineGroupTriggers(fieldDefinition, groupDefinition, targets, groupName);
        log_debug_printf(_logname, "%s\n", "");
    }
}

/**
 * Define trigger for a given field to reference the given targets.
 *
 * @param fieldDefinition the field definition who's trigger definition will be updated
 * @param groupDefinition the group definition to reference
 * @param triggerNames the field's trigger target names
 * @param groupName the name of the group
 */
void GroupConfigProcessor::defineGroupTriggers(FieldDefinition& fieldDefinition, const GroupDefinition& groupDefinition,
                                               const TriggerNames& triggerNames, const std::string& groupName) {
    for (auto&& triggerName: triggerNames) {
        // If the target is star then map to all fields
        if (triggerName == "*") {
            for (auto& targetedFieldDefinition: groupDefinition.fields) {
                if (!targetedFieldDefinition.channel.empty()) {
                    fieldDefinition.triggerNames.insert(targetedFieldDefinition.name);
                    log_debug_printf(_logname, "%s, ", targetedFieldDefinition.name.c_str());
                }
            }
        } else {
            // otherwise map to the specific target if it exists
            auto it(groupDefinition.fieldMap.find(triggerName));
            if (it == groupDefinition.fieldMap.end()) {
                fprintf(stderr, "Error: Group \"%s\" defines triggers to nonexistent field \"%s\" \n",
                        groupName.c_str(), triggerName.c_str());
                continue;
            }
            auto index = it->second;
            auto& targetedField = groupDefinition.fields.at(index);
            assert(targetedField.name == triggerName);

            // And if it references a PV
            if (targetedField.channel.empty()) {
                log_debug_printf(_logname, "<ignore: %s>, ", targetedField.name.c_str());
            } else {
                fieldDefinition.triggerNames.insert(targetedField.name);
                log_debug_printf(_logname, "%s, ", targetedField.name.c_str());
            }
        }
    }
}

/**
 * Process the defined groups to create the final Group objects containing PVStructure templates and all the
 * infrastructure needed to respond to PVAccess requests linked to the underlying IOC database
 *
 * 1. Builds Groups and Fields from Group Definitions
 * 2. Build PVStructures for each Group and discard those w/o a dbChannel
 * 3. Build the lockers for each group and field based on their triggers
 */
void GroupConfigProcessor::createGroups() {
    auto& groupMap = config.groupMap;


    // First pass: Create groups and get array capacities
    for (auto& groupDefinitionMapEntry: groupDefinitionMap) {
        auto& groupName = groupDefinitionMapEntry.first;
        auto& groupDefinition = groupDefinitionMapEntry.second;
        try {
            // Create group
            auto pair = groupMap.emplace(std::piecewise_construct,
                                         std::forward_as_tuple(groupName),
                                         std::forward_as_tuple(groupName,
                                                               groupDefinition.atomic != False));
            if (!pair.second) {
                throw std::runtime_error("Group name already in use");
            }
            auto& group = pair.first->second;

            // Initialise the given group's fields from the given group definition
            initialiseGroupFields(group, groupDefinition);
        } catch (std::exception& e) {
            fprintf(stderr, "%s: Error Group not created: %s\n", groupName.c_str(), e.what());
        }
    }

    // Second Pass: assemble group's PV structure definitions and db locker
    for (auto& groupDefinitionMapEntry: groupDefinitionMap) {
        auto& groupName = groupDefinitionMapEntry.first;
        auto& groupDefinition = groupDefinitionMapEntry.second;
        try {
            auto it(groupMap.find(groupName));
            assert(it!=groupMap.end());
            auto& group =it->second;
            // Initialise the given group's db locks
            initialiseDbLocker(group);
            // Initialize the given group's triggers and associated db locks
            initialiseTriggers(group, groupDefinition);
            // Initialise the given group's value type
            initialiseValueTemplate(group, groupDefinition);
        } catch (std::exception& e) {
            fprintf(stderr, "%s: Error Group not created: %s\n", groupName.c_str(), e.what());
        }
    }
}

/**
 * Initialise the given group's fields from the given configuration.
 *
 * The group configuration contains a set of fields.  These fields define the structure of the group.
 * Dot notation (a.b.c) define substructures with subfields, and bracket notation (a[1].b) define
 * structure arrays. Each configuration reference points to a database record (channel).
 * This function uses the configuration to define the group fields that are required
 * to link to the specified database records.  This means that one group field is created for each
 * referenced database record.
 *
 * @param group the group to store fields->channel mappings
 * @param groupDefinition the group definition we're reading group information from
 */
void GroupConfigProcessor::initialiseGroupFields(Group& group, const GroupDefinition& groupDefinition) {
    // Reserve enough space for fields with channels
    group.fields.reserve(groupDefinition.fields.size());

    // for each field
    for (auto& fieldDefinition: groupDefinition.fields) {
        group.fields.emplace_back(fieldDefinition);
    }
}

/**
 * Initialise the given group's value template from the given group definition.
 * Creates the top level PVStructure for the group and stores it in valueTemplate.
 *
 * @param group the group we're setting
 * @param groupDefinition the group definition we're reading from
 */
void GroupConfigProcessor::initialiseValueTemplate(Group& group, const GroupDefinition& groupDefinition) {
    using namespace pvxs::members;
    // We will go add members to this list, and then add them to the group's valueTemplate before returning
    std::vector<Member> groupMembersToAdd;

    // Add default member: record
    groupMembersToAdd.push_back({
                                    Struct("record", {
                                        Struct("_options", {
                                            Int32("queueSize"),
                                            Bool("atomic")
                                        })
                                    })
                                });

    // for each field add any required members to the list
    addTemplatesForDefinedFields(groupMembersToAdd, group, groupDefinition);

    // Add all the collected group members to the group type
    TypeDef groupType(TypeCode::Struct, groupDefinition.structureId, {});
    groupType += groupMembersToAdd;

    // create the group's valueTemplate from the group type
    auto groupValueTemplate = groupType.create();
    group.valueTemplate = std::move(groupValueTemplate);
}

/**
 * Initialise triggers.  This function will initialize the triggers so that each field contains the list of fields
 * that subscription updates will also trigger to be fetched.  It will also create lockers in each field that will
 * be prepared to lock those fields during the subscription update.  The configuration information for the
 * triggers has already been loaded into the provided group definition.
 * Note that this function must be called after the fields have been created in group as the triggers are
 * initialized with a set of pointers to other fields.
 *
 * @param group the group of fields who's triggers are to be configured
 * @param groupDefinition the group definition
 */
void GroupConfigProcessor::initialiseTriggers(Group& group, const GroupDefinition& groupDefinition) {
    std::vector<dbCommon*> references;
    // For all fields in the group
    for (auto& fieldDefinition: groupDefinition.fields) {
        // As long as it has a channel specified
        if (!fieldDefinition.channel.empty()) {
            auto& field = group[fieldDefinition.name];
            references.clear();
            // Look at the fields that it triggers
            for (auto& referencedFieldName: fieldDefinition.triggerNames) {
                auto referencedFieldIt = groupDefinition.fieldMap.find(referencedFieldName);
                if (referencedFieldIt != groupDefinition.fieldMap.end()) {
                    auto& referencedFieldIndex = referencedFieldIt->second;
                    auto& referencedField = group.fields[referencedFieldIndex];
                    // Add new trigger reference
                    field.triggers.emplace_back(&referencedField);
                    // Add new lock record
                    if (referencedField.value) {
                        references.emplace_back(referencedField.value->addr.precord);
                    }
                }
            }

            // Make the locks
            field.lock = DBManyLock(references);
        }
    }
}

/**
 * Add members to the given vector of members, for any fields in the given group.
 *
 * @param groupMembers the vector to add members to
 * @param group the given group
 * @param groupDefinition the source group definition
 */
void GroupConfigProcessor::addTemplatesForDefinedFields(std::vector<Member>& groupMembers, Group& group,
                                                        const GroupDefinition& groupDefinition) {
    for (auto& fieldDefinition: groupDefinition.fields) {
        auto& field = group[fieldDefinition.name];
        auto& pDbChannel(field.value);
        switch(fieldDefinition.info.type) {
        case MappingInfo::Scalar:
            addMembersForScalarType(groupMembers, field, pDbChannel);
            break;
        case MappingInfo::Plain:
            addMembersForPlainType(groupMembers, field, pDbChannel);
            break;
        case MappingInfo::Any:
            addMembersForAnyType(groupMembers, field);
            break;
        case MappingInfo::Meta:
            addMembersForMetaData(groupMembers, field);
            break;
        case MappingInfo::Proc: // nothing to do here
            break;
        case MappingInfo::Structure:
            addMembersForStructureType(groupMembers, field);
            break;
        case MappingInfo::Const:
        {
            TypeDef def(field.info.cval);
            if(field.fieldName.empty()) { // placing in root
                throw std::logic_error("TODO: \"\":{+type:\"const\" ...} not currently supported");
            } else {
                std::vector<Member> newMem({def.as(field.fieldName.leafFieldName())});
                setFieldTypeDefinition(groupMembers, field.fieldName, newMem);
            }
        }
            break;
        }
    }
}

/**
 * To process key part of json nodes.  This will be followed by a boolean, integer, block, or null
 *
 * @param parserContext the parser context
 * @param key the key
 * @param keyLength the length of the key
 * @return non-zero if successful
 */
static
int parserCallbackKey(void* parserContext, const unsigned char* key, const size_t keyLength) {
    return GroupConfigProcessor::yajlProcess(parserContext, [&key, &keyLength](GroupProcessorContext* self) {
        if (keyLength == 0 && self->depth != 2) {
            throw std::runtime_error("empty group or key name not allowed");
        }

        std::string name((const char*)key, keyLength);

        if (self->depth == 1) {
            self->groupName.swap(name);
        } else if (self->depth == 2) {
            self->field.swap(name);
        } else if (self->depth == 3) {
            self->key.swap(name);
        } else {
            throw std::logic_error("Malformed json group definition: too many nesting levels");
        }

        return 1;
    });
}

/**
 * To process null json nodes
 *
 * @param parserContext the parser context
 * @return non-zero if successful
 */
static
int parserCallbackNull(void* parserContext) {
    return GroupConfigProcessor::yajlProcess(parserContext, [](GroupProcessorContext* self) {
        self->assign(Value());
        return 1;
    });
}

/**
 * To process boolean json nodes
 *
 * @param parserContext the parser context
 * @param booleanValue the boolean value
 * @return non-zero if successful
 */
static
int parserCallbackBoolean(void* parserContext, int booleanValue) {
    return GroupConfigProcessor::yajlProcess(parserContext, [&booleanValue](GroupProcessorContext* self) {
        auto value = pvxs::TypeDef(TypeCode::Bool).create();
        value = booleanValue;
        self->assign(value);
        return 1;
    });
}

/**
 * To process integer json nodes
 *
 * @param parserContext the parser context
 * @param integerVal the integer value
 * @return non-zero if successful
 */
static
int parserCallbackInteger(void* parserContext, long long integerVal) {
    return GroupConfigProcessor::yajlProcess(parserContext, [&integerVal](GroupProcessorContext* self) {
        auto value = pvxs::TypeDef(TypeCode::Int64).create();
        value = (int64_t)integerVal;
        self->assign(value);
        return 1;
    });
}

/**
 * To process double json nodes
 *
 * @param parserContext the parser context
 * @param doubleVal the double value
 * @return non-zero if successful
 */
static
int parserCallbackDouble(void* parserContext, double doubleVal) {
    return GroupConfigProcessor::yajlProcess(parserContext, [&doubleVal](GroupProcessorContext* self) {
        auto value = pvxs::TypeDef(TypeCode::Float64).create();
        value = doubleVal;
        self->assign(value);
        return 1;
    });
}

/**
 * To process string json nodes
 *
 * @param parserContext the parser context
 * @param stringVal the string value
 * @param stringLen the string length
 * @return non-zero if successful
 */
static
int parserCallbackString(void* parserContext, const unsigned char* stringVal,
                                               const size_t stringLen) {
    return GroupConfigProcessor::yajlProcess(parserContext, [&stringVal, &stringLen](GroupProcessorContext* self) {
        std::string val((const char*)stringVal, stringLen);
        auto value = pvxs::TypeDef(TypeCode::String).create();
        value = val;
        self->assign(value);
        return 1;
    });
}

/**
 * To start processing new json blocks
 *
 * @param parserContext the parser context
 * @return non-zero if successful
 */
static
int parserCallbackStartBlock(void* parserContext) {
    return GroupConfigProcessor::yajlProcess(parserContext, [](GroupProcessorContext* self) {
        self->depth++;
        if (self->depth > 3) {
            throw std::runtime_error("Group field def. can't contain Object (too deep)");
        }
        return 1;
    });
}

/**
 * To end processing the current json block
 *
 * @param parserContext the parser context
 * @return non-zero if successful
 */
static
int parserCallbackEndBlock(void* parserContext) {
    return GroupConfigProcessor::yajlProcess(parserContext, [](GroupProcessorContext* self) {
        assert(self->key.empty()); // cleared in assign()

        if (self->depth == 3) {
            self->key.clear();
        } else if (self->depth == 2) {
            self->field.clear();
        } else if (self->depth == 1) {
            self->groupName.clear();
        } else {
            throw std::logic_error("Internal error in json parser: invalid depth");
        }
        self->depth--;

        return 1;
    });
}



/**
 * These are the callbacks designated by yajl for its parser functions
 * They must be defined in this order.
 * Note that we don't use number, or arrays
 */
static const
yajl_callbacks yajlParserCallbacks{
    &parserCallbackNull,
    &parserCallbackBoolean,
    &parserCallbackInteger,
    &parserCallbackDouble,
    nullptr,            // number
    &parserCallbackString,
    &parserCallbackStartBlock,
    &parserCallbackKey,
    &parserCallbackEndBlock,
    nullptr,            // start_array,
    nullptr,            // end_array,
};

/**
 * Parse the given json string as a group configuration part for the given dbRecord
 * name and extract group definition into our groupDefinitionMap
 *
 * @param jsonGroupDefinition the given json string representing a group configuration
 * @param dbRecordName the name of the dbRecord
 */
void GroupConfigProcessor::parseConfigString(const char* jsonGroupDefinition, const char* dbRecordName) {
#ifndef EPICS_YAJL_VERSION
    yajl_parser_config parserConfig;
    memset(&parserConfig, 0, sizeof(parserConfig));
    parserConfig.allowComments = 1;
    parserConfig.checkUTF8 = 1;
#endif

    // Convert the json string to a stream to be passed to the json parser
    std::istringstream jsonGroupDefinitionStream(jsonGroupDefinition);

    std::string channelPrefix;

    if (dbRecordName) {
        channelPrefix = dbRecordName;
        channelPrefix += '.';
    }

    // Create a parser context for the parser
    GroupProcessorContext parserContext(channelPrefix, this);

#ifndef EPICS_YAJL_VERSION
    YajlHandler handle(yajl_alloc(&yajlParserCallbacks, &parserConfig, NULL, &parserContext));
#else

    // Create a callback handler for the parser
    YajlCallbackHandler callbackHandler(yajl_alloc(&yajlParserCallbacks, nullptr, &parserContext));

    // Configure the parser with the handler and some options (allow comments)
    yajl_config(callbackHandler, yajl_allow_comments, 1);
#endif

    // Parse the json stream for group definitions using the configured parser
    if (!yajlParseHelper(jsonGroupDefinitionStream, callbackHandler)) {
        throw std::runtime_error(parserContext.errorMessage);
    }
}

/**
 * Get the info field string from the given dbEntry for the given key.
 * If the key is not found then return the given default value.
 *
 * @param dbEntry the given dbEntry
 * @param key the key to get the info field for
 * @param defaultValue the default value to return in case its not found
 * @return the string for the info key
 */
const char* GroupConfigProcessor::infoField(DBEntry& dbEntry, const char* key, const char* defaultValue) {
    // If field not found then return default value
    if (dbFindInfo(dbEntry, key)) {
        return defaultValue;
    }

    // Otherwise return the info string
    return dbGetInfoString(dbEntry);
}

/**
 * Add a scalar field as the prescribed subfield by adding the appropriate members to the given members list
 *
 * e.g: fieldName: "a.b", type => NTScalar, leaf = {NTScalar{}} - a single structure with ID, and members corresponding to NTScalar
 *    return {Struct{a: Struct{b: NTScalar{}}}} - single element vector
 *    effect: group members += {Struct{a: Struct{b: NTScalar{}}}} - adds NTScalar at a.b
 *
 * @param groupMembers the given group members to update
 * @param groupField the field used to determine the members to add and how to create them
 * @param pDbChannel the db channel to get information on what scalar type to create
 */
void GroupConfigProcessor::addMembersForScalarType(std::vector<Member>& groupMembers, const Field& groupField,
                                                   const Channel& pDbChannel) {
    using namespace pvxs::members;
    assert(!groupField.fieldName.empty()); // Must not call with empty field name

    TypeDef leaf = getTypeDefForChannel(pDbChannel);

    std::vector<Member> newScalarMembers({ leaf.as(groupField.fieldName.leafFieldName()) });
    setFieldTypeDefinition(groupMembers, groupField.fieldName, newScalarMembers);
}

/**
 * Add members to the given vector of members for a plain type field (not Normative Type), that is referenced by the
 * given group field.  The provided channel is used to get the type of the leaf member to create.
 *
 * @param groupMembers the vector of members to add to
 * @param groupField the given group field
 * @param pDbChannel the channel used to get the type of the leaf member
 */
void GroupConfigProcessor::addMembersForPlainType(std::vector<Member>& groupMembers, const Field& groupField,
                                                  const Channel &pDbChannel) {
    assert(!groupField.fieldName.empty()); // Must not call with empty field name

    // Get the type for the leaf
    auto leafCode(IOCSource::getChannelValueType(pDbChannel, true));
    TypeDef leaf(leafCode);
    std::vector<Member> newScalarMembers({ leaf.as(groupField.fieldName.leafFieldName()) });
    setFieldTypeDefinition(groupMembers, groupField.fieldName, newScalarMembers);
}

/**
* Add members to the given vector of members for an `any` type field - a field that contains any scalar type,
* that is referenced by the given group field.
*
* @param groupMembers the vector of members to add to
* @param groupField the given group field
 */
void GroupConfigProcessor::addMembersForAnyType(std::vector<Member>& groupMembers,
                                                const Field& groupField) {
    assert(!groupField.fieldName.empty()); // Must not call with empty field name
    std::vector<Member> newScalarMembers({
                                             Member(TypeCode::Any, groupField.fieldName.leafFieldName())
                                         });
    setFieldTypeDefinition(groupMembers, groupField.fieldName, newScalarMembers);
}

/**
 * Add ID fields to the prescribed subfield by adding the appropriate members to the
 * given members list.  This will work by creating a leaf node Struct/StructA that has
 * the ID specified for the field. This only works if the referenced field is a structure i.e an NT type.
 * Throws an error if we try to apply this to the top level as there is already a mechanism for that.
 *
 * @param groupMembers the given group members to update
 * @param groupField the group field used to determine the members to add and how to create them
 */
void GroupConfigProcessor::addMembersForStructureType(std::vector<Member>& groupMembers,
                                                      const Field& groupField) {
    using namespace pvxs::members;

    std::vector<Member> newIdMembers(
                { groupField.isArray ? StructA(groupField.name, groupField.id, {}) : Struct(groupField.name, groupField.id, {}) });

    // Add ID to the group members at the position determined by group field name
    setFieldTypeDefinition(groupMembers, groupField.fieldName, newIdMembers);
}

/**
 * Add metadata fields to the prescribed subfield (or top level) by adding the appropriate members to the
 * given members list.
 *
 * @param groupMembers the given group members to update
 * @param groupField the group field used to determine the members to add and how to create them
 */
void GroupConfigProcessor::addMembersForMetaData(std::vector<Member>& groupMembers, const Field& groupField) {
    using namespace pvxs::members;
    std::vector<Member> newMetaMembers({
                                           Struct("alarm", "alarm_t", {
                                               Int32("severity"),
                                               Int32("status"),
                                               String("message"),
                                           }),
                                           nt::TimeStamp{}.build().as("timeStamp"),
                                       });

    // Add metadata to the group members at the position determined by group field name
    setFieldTypeDefinition(groupMembers, groupField.fieldName, newMetaMembers, false);
}

/**
 * Get the type definition to use for a given channel.  This must only be used for Normative Types.
 * @param pDbChannel the channel to define the type definition for
 * @return the TypeDef for the channel
 */
TypeDef GroupConfigProcessor::getTypeDefForChannel(const Channel& pDbChannel) {
    // Get the type for the leaf
    auto leafCode(IOCSource::getChannelValueType(pDbChannel, true));
    TypeDef leaf;

    // Create the leaf
    auto dbfType = dbChannelFinalFieldType(pDbChannel);
    if (dbfType == DBF_ENUM || dbfType == DBF_MENU) {
        leaf = nt::NTEnum{}.build();
    } else {
        bool display = true;
        bool control = true;
        bool valueAlarm = (dbfType != DBF_STRING);
        leaf = nt::NTScalar{ leafCode, display, control, valueAlarm, true }.build();
    }
    return leaf;
}

/**
 * Update the given group members by creating a new members list that uses the given field name
 * to determine the nesting of members required to place the given leaf members.
 *
 * Examples:
 * 1) fieldName: "",  type => metadata, leaf = {Struct{alarm}, Struct{timestamp}}
 *    return {Struct{alarm}, Struct{timestamp}}
 *    effect: group members += {Struct{alarm}, Struct{timestamp}}
 *
 * 2) fieldName: "a.b", type => NTScalar, leaf = {NTScalar{}} - a single structure with ID, and members corresponding to NTScalar
 *    return {Struct{a: Struct{b: NTScalar{}}}} - single element vector
 *    effect: group members += {Struct{a: Struct{b: NTScalar{}}}} - adds NTScalar at a.b
 *
 * 3) fieldName: "a.c", type => plain double, leaf = {Float64}
 *    return {Struct{a: Struct{c: {Float64}}}} - single element vector
 *    effect group members += {Struct{a: Struct{c: {Float64}}}} - adds plain double at a.c
 *
 * 4) fieldName: "a.b", type => metadata, leaf = {Struct{alarm}, Struct{timestamp}}
 *    return {Struct{a: Struct{b: {Struct{alarm}, Struct{timestamp}}}}} - single element vector
 *    effect group members += {Struct{a: Struct{b: {Struct{alarm}, Struct{timestamp}}}}} - add alarm and timestamp info to existing NTScalar at a.b
 *
 * @param groupMembers the group members to add new members to
 * @param fieldName The field name to use to determine how to create the members
 * @param leafMembers the leaf member or members to place at the leaf of the members tree
 * @param isLeaf If true, leafMembers are added to the parent of the leaf.
 *               If false, leafMembers are added as members of a Struct which is the leaf
 */
void GroupConfigProcessor::setFieldTypeDefinition(std::vector<Member>& groupMembers, const FieldName& fieldName,
                                                  const std::vector<Member>& leafMembers, bool isLeaf) {
    using namespace pvxs::members;

    // Make up the full structure starting from the leaf
    if (fieldName.empty()) {
        // Add all the members (or just one) to the list of group members
        groupMembers.insert(groupMembers.end(), leafMembers.begin(), leafMembers.end());
    } else {
        std::vector<Member> childrenToAdd;

        if (!isLeaf) {
            childrenToAdd = leafMembers;
        }

        // iterate name in reverse order.  rightmost -> leftmost, leaf -> root
        for (auto componentNumber = fieldName.size(); componentNumber > 0; componentNumber--) {
            const auto& component = fieldName[componentNumber - 1];

            // If this is the leaf then use the leaf members
            if (isLeaf) {
                isLeaf = false;
                childrenToAdd = leafMembers;
            } else if (component.isArray()) {
                // if this is an array then enclose in a structure array
                childrenToAdd = { StructA(component.name, childrenToAdd) };
            } else { // otherwise a simple structure
                childrenToAdd = { Struct(component.name, childrenToAdd) };
            }
        }
        groupMembers.insert(groupMembers.end(), childrenToAdd.begin(), childrenToAdd.end());
    }
}

/**
 * Helper function to wrap processing of json lexical elements.
 * All exceptions are caught and translated into processing context messages
 *
 * @param parserContext the parser context
 * @param pFunction the lambda to call to process the given element
 * @return the value returned from the lambda function
 */
int
GroupConfigProcessor::yajlProcess(void* parserContext, const std::function<int(GroupProcessorContext*)>& pFunction) {
    auto* pContext = (GroupProcessorContext*)parserContext;
    int returnValue = -1;
    try {
        returnValue = pFunction(pContext);
    } catch (std::exception& e) {
        if (pContext->errorMessage.empty()) {
            pContext->errorMessage = e.what();
        }
    }
    return returnValue;
}

/**
 * Parse the given stream as a json group definition using the given json parser handler
 *
 * @param jsonGroupDefinitionStream the given json group definition stream
 * @param handle the handler
 * @return true if successful
 */
bool GroupConfigProcessor::yajlParseHelper(std::istream& jsonGroupDefinitionStream, yajl_handle handle) {
    unsigned linenum = 0;
#ifndef EPICS_YAJL_VERSION
    bool done = false;
#endif

    std::string line;
    while (std::getline(jsonGroupDefinitionStream, line)) {
        linenum++;

#ifndef EPICS_YAJL_VERSION
        if(done) {
            check_trailing(line);
            continue;
        }
#endif

        // Parse the next line from the json group definition
        yajl_status status = yajl_parse(handle, (const unsigned char*)line.c_str(), line.size());

        switch (status) {
        case yajl_status_ok: {
            size_t consumed = yajl_get_bytes_consumed(handle);

            if (consumed < line.size()) {
                size_t idx = line.find_first_not_of(" \t\n\r", consumed);
                if (idx != std::string::npos) {
                    // TODO: detect the end of potentially multi-line comments...
                    // for now trailing comments not allowed
                    throw std::runtime_error("Trailing content after } are not allowed");
                }
            }

#ifndef EPICS_YAJL_VERSION
            done = true;
#endif
            break;
        }
        case yajl_status_client_canceled:
            return false;
#ifndef EPICS_YAJL_VERSION
        case yajl_status_insufficient_data:
            // continue with next line
            break;
#endif
        case yajl_status_error: {
            std::ostringstream errorMessage;
            unsigned char* raw = yajl_get_error(handle, 1, (const unsigned char*)line.c_str(), line.size());
            if (!raw) {
                errorMessage << "Unknown error on line " << linenum;
            } else {
                try {
                    errorMessage << "Error on line " << linenum << " : " << (const char*)raw;
                } catch (...) {
                    yajl_free_error(handle, raw);
                    throw;
                }
                yajl_free_error(handle, raw);
            }
            throw std::runtime_error(errorMessage.str());
        }
        }
    }

    if (!jsonGroupDefinitionStream.eof() || jsonGroupDefinitionStream.bad()) {
        std::ostringstream msg;
        msg << "I/O error after line " << linenum;
        throw std::runtime_error(msg.str());

#ifndef EPICS_YAJL_VERSION
    } else if(!done) {
        switch(yajl_parse_complete(handle)) {
#else
    } else {
        switch (yajl_complete_parse(handle)) {
#endif
        case yajl_status_ok:
            break;
        case yajl_status_client_canceled:
            return false;
#ifndef EPICS_YAJL_VERSION
        case yajl_status_insufficient_data:
            throw std::runtime_error("unexpected end of input");
#endif
        case yajl_status_error:
            throw std::runtime_error("Error while completing parsing");
        }
    }
    return true;
}

/**
 * Initialise the dbLocker in the group.  List all the channels in the group and add them to a list.  Then
 * create the locker from this list.
 *
 * @param group the group to create the locker for
 */
void GroupConfigProcessor::initialiseDbLocker(Group& group) {
    for (auto& field: group.fields) {
        dbChannel* pValueChannel = field.value;
        dbChannel* pPropertiesChannel = field.properties;
        if (pValueChannel) {
            group.value.channels.emplace_back(pValueChannel->addr.precord);
        }
        if (pPropertiesChannel) {
            group.properties.channels.emplace_back(pPropertiesChannel->addr.precord);
        }
    }
    group.value.lock = DBManyLock(group.value.channels);
    group.properties.lock = DBManyLock(group.properties.channels);
}

} // ioc
} // pvxs
