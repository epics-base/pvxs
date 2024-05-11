/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 *
 * Author George S. McIntyre <george@level-n.com>, 2023
 *
 */

#ifndef PVXS_GROUPCONFIGPROCESSOR_H
#define PVXS_GROUPCONFIGPROCESSOR_H

#include <string>
#include <functional>

#include <yajl_parse.h>

#include "dbentry.h"
#include "group.h"
#include "groupconfig.h"
#include "groupdefinition.h"

namespace pvxs {
namespace ioc {

// Pre-declare context class
class GroupProcessorContext;

/**
 * Class to parse group configuration that has been defined in db configuration files.
 * This involves extracting info fields named "Q:Group" from the database configuration
 * and converting them to Groups.
 */
class GroupConfigProcessor {
    // populated by defineGroups()
    std::map<std::string, GroupDefinition> groupDefinitionMap;

public:
    std::map<std::string, GroupConfig> groupConfigMap;

    // Group processing warning messages if not empty
    std::string groupProcessingWarnings;

    IOCGroupConfig& config;

    GroupConfigProcessor();

    void validateGroups();
    void defineGroups();
    void createGroups();
    static const char* infoField(DBEntry& dbEntry, const char* key, const char* defaultValue = nullptr);
    static void initialiseGroupFields(Group& group, const GroupDefinition& groupDefinition);
    static void initialiseValueTemplate(Group& group, const GroupDefinition& groupDefinition);
    void loadConfigFiles();
    void loadConfigFromDb();
    void resolveTriggerReferences();
    static void setFieldTypeDefinition(std::vector<Member>& groupMembers, const FieldName& fieldName,
                                       const std::vector<Member>& leafMembers, bool isLeaf = true);
    static int yajlProcess(void* parserContext, const std::function<int(GroupProcessorContext*)>& pFunction);

private:
    static void
    addTemplatesForDefinedFields(std::vector<Member>& groupMembers, Group& group,
                                 const GroupDefinition& groupDefinition);
    static void addMembersForAnyType(std::vector<Member>& groupMembers, const Field& groupField);
    static void addMembersForMetaData(std::vector<Member>& groupMembers, const Field& groupField);
    static void addMembersForPlainType(std::vector<Member>& groupMembers, const Field& groupField,
                                       const Channel& pDbChannel);
    static void addMembersForScalarType(std::vector<Member>& groupMembers, const Field& groupField,
                                        const Channel &pDbChannel);
    static void addMembersForStructureType(std::vector<Member>& groupMembers, const Field& groupField);
    static void defineGroupTriggers(FieldDefinition& fieldDefinition, const GroupDefinition& groupDefinition,
                                    const TriggerNames& triggerNames, const std::string& groupName);
    static void defineFields(GroupDefinition& groupDefinition, const GroupConfig& groupConfig,
                             const std::string& groupName);
    static void resolveGroupTriggerReferences(GroupDefinition& groupDefinition, const std::string& groupName);
    static void defineAtomicity(GroupDefinition& groupDefinition, const GroupConfig& groupConfig,
                                const std::string& groupName);
    void defineFieldSortOrder();
    void parseConfigString(const char* jsonGroupDefinition, const char* dbRecordName = nullptr);
    static void defineTriggers(GroupDefinition& groupDefinition, const FieldConfig& fieldConfig,
                               const std::string& fieldName);
    static bool yajlParseHelper(std::istream& jsonGroupDefinitionStream, yajl_handle handle);
    static void initialiseDbLocker(Group& group);
    static void initialiseTriggers(Group& group, const GroupDefinition& groupDefinition);
    static TypeDef getTypeDefForChannel(const Channel &pDbChannel);
};

} // ioc
} // pvxs

#endif //PVXS_GROUPCONFIGPROCESSOR_H

