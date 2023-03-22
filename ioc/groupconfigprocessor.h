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

#include <yajl_parse.h>

#include "dbentry.h"
#include "groupconfig.h"
#include "groupdefinition.h"
#include "iocserver.h"

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
    GroupDefinitionMap groupDefinitionMap;

    /**
     * These are the callbacks designated by yajl for its parser functions
     * They must be defined in this order.
     * Note that we don't use number, or arrays
     */
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

public:
    GroupConfigMap groupConfigMap;

    // Group processing warning messages if not empty
    std::string groupProcessingWarnings;

    GroupConfigProcessor() = default;

    static void checkForTrailingCommentsAtEnd(const std::string& line);
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
    static void addMembersForId(std::vector<Member>& groupMembers, const Field& groupField);
    static void addMembersForMetaData(std::vector<Member>& groupMembers, const Field& groupField);
    static void addMembersForPlainType(std::vector<Member>& groupMembers, const Field& groupField,
                                       const dbChannel* pDbChannel);
    static void addMembersForScalarType(std::vector<Member>& groupMembers, const Field& groupField,
                                        const dbChannel* pDbChannel);
    static void addMembersForStructureType(std::vector<Member>& groupMembers, const Field& groupField);
    static void defineGroupTriggers(FieldDefinition& fieldDefinition, const GroupDefinition& groupDefinition,
                                    const TriggerNames& triggerNames, const std::string& groupName);
    static void defineFields(GroupDefinition& groupDefinition, const GroupConfig& groupConfig,
                             const std::string& groupName);
    static void resolveGroupTriggerReferences(GroupDefinition& groupDefinition, const std::string& groupName);
    static void defineAtomicity(GroupDefinition& groupDefinition, const GroupConfig& groupConfig,
                                const std::string& groupName);
    void defineFieldSortOrder();
    static void resolveSelfTriggerReferences(GroupDefinition& groupDefinition);
    static int parserCallbackBoolean(void* parserContext, int booleanValue);
    static int parserCallbackDouble(void* parserContext, double doubleVal);
    static int parserCallbackEndBlock(void* parserContext);
    static int parserCallbackInteger(void* parserContext, long long int integerVal);
    static int parserCallbackKey(void* parserContext, const unsigned char* key, size_t keyLength);
    static int parserCallbackNull(void* parserContext);
    static int parserCallbackStartBlock(void* parserContext);
    static int parserCallbackString(void* parserContext, const unsigned char* stringVal, size_t stringLen);
    void parseConfigString(const char* jsonGroupDefinition, const char* dbRecordName = nullptr);
    static void defineTriggers(GroupDefinition& groupDefinition, const FieldConfig& fieldConfig,
                               const std::string& fieldName);
    static bool yajlParseHelper(std::istream& jsonGroupDefinitionStream, yajl_handle handle);
    static void initialiseDbLocker(Group& group);
    static void initialiseTriggers(Group& group, const GroupDefinition& groupDefinition);
    static TypeDef getTypeDefForChannel(const dbChannel* pDbChannel);
};

} // ioc
} // pvxs

#endif //PVXS_GROUPCONFIGPROCESSOR_H

