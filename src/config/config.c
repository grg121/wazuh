/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Unified function to read the configuration */

#include "shared.h"
#include "os_xml/os_xml.h"
#include "config.h"
#include "global-config.h"

/* Prototypes */
static int read_main_elements(const OS_XML *xml, int modules,
                              XML_NODE node,
                              void *d1,
                              void *d2,
                              char **output);


/* Read the main elements of the configuration */
static int read_main_elements(const OS_XML *xml, int modules,
                              XML_NODE node,
                              void *d1,
                              void *d2,
                              char **output)
{
    int i = 0;
    const char *osglobal = "global";                    /* Server Config */
    const char *osrules = "ruleset";                    /* Server Config */
    const char *ossyscheck = "syscheck";                /* Agent Config  */
    const char *osrootcheck = "rootcheck";              /* Agent Config  */
    const char *osalerts = "alerts";                    /* Server Config */
    const char *osemailalerts = "email_alerts";         /* Server Config */
    const char *osdbd = "database_output";              /* Server Config */
    const char *oscsyslogd = "syslog_output";           /* Server Config */
    const char *oscagentless = "agentless";             /* Server Config */
    const char *oslocalfile = "localfile";              /* Agent Config  */
    const char *osremote = "remote";                    /* Agent Config  */
    const char *osclient = "client";                    /* Agent Config  */
    const char *osbuffer = "client_buffer";             /* Agent Buffer Config  */
    const char *oscommand = "command";                  /* ? Config      */
    const char *osreports = "reports";                  /* Server Config */
    const char *osintegratord = "integration";          /* Server Config */
    const char *osactive_response = "active-response";  /* Agent Config  */
    const char *oswmodule = "wodle";                    /* Wodle - Wazuh Module  */
    const char *oslabels = "labels";                    /* Labels Config */
    const char *osauthd = "auth";                       /* Authd Config */
    const char *oslogging = "logging";                  /* Logging Config */
    const char *oscluster = "cluster";                  /* Cluster Config */
    const char *ossocket = "socket";                    /* Socket Config */
    const char *ossca = "sca";                          /* Security Configuration Assessment */
    const char *osvulndet = "vulnerability-detector";   /* Vulnerability Detector Config */
#ifndef WIN32
    const char *osfluent_forward = "fluent-forward";     /* Fluent forwarder */
#endif

    while (node[i]) {
        XML_NODE chld_node = NULL;

        if (!node[i]->element) {
            if (output == NULL){
                merror(XML_ELEMNULL);                    
            } else {
                wm_strcat(output, "Invalid NULL element in the configuration", '\n');
            }
            goto fail;
        }

        chld_node = OS_GetElementsbyNode(xml, node[i]);

        if (chld_node && (strcmp(node[i]->element, osglobal) == 0)) {
            if (((modules & CGLOBAL) || (modules & CMAIL))
                    && (Read_Global(chld_node, d1, d2, output) < 0)) {
                goto fail;
            }
        } else if (chld_node && (strcmp(node[i]->element, osemailalerts) == 0)) {
            if ((modules & CMAIL) && (Read_EmailAlerts(chld_node, d1, d2, output) < 0)) {
                goto fail;
            }
        } else if (chld_node && (strcmp(node[i]->element, osdbd) == 0)) {
            if ((modules & CDBD) && (Read_DB(chld_node, d1, d2, output) < 0)) {
                goto fail;
            }
        } else if (chld_node && (strcmp(node[i]->element, oscsyslogd) == 0)) {
            if ((modules & CSYSLOGD) && (Read_CSyslog(chld_node, d1, d2, output) < 0)) {
                goto fail;
            }
        } else if(chld_node && (strcmp(node[i]->element, osintegratord) == 0)) {
            if((modules & CINTEGRATORD) && (Read_Integrator(chld_node, d1, d2, output) < 0)) {
                goto fail;
            }
        } else if (chld_node && (strcmp(node[i]->element, oscagentless) == 0)) {
            if ((modules & CAGENTLESS) && (Read_CAgentless(chld_node, d1, d2, output) < 0)) {
                goto fail;
            }
        } else if (chld_node && (strcmp(node[i]->element, osrules) == 0)) {
            if ((modules & CRULES) && (Read_Rules(chld_node, d1, d2, output) < 0)) {
                goto fail;
            }
        } else if (strcmp(node[i]->element, ossyscheck) == 0) {
<<<<<<< HEAD
            if ((modules & CSYSCHECK) && (Read_Syscheck(xml, chld_node, d1, d2, modules) < 0)) {
=======
            if ((modules & CSYSCHECK) && (Read_Syscheck(xml, chld_node, d1, d2, output) < 0)) {
>>>>>>> Introduce variable output to ReadConfig
                goto fail;
            }
            if ((modules & CGLOBAL) && (Read_GlobalSK(chld_node, d1, d2, output) < 0)) {
                goto fail;
            }
        } else if (strcmp(node[i]->element, osrootcheck) == 0) {
            if ((modules & CROOTCHECK) && (Read_Rootcheck(chld_node, d1, d2, output) < 0)) {
                goto fail;
            }
        } else if (chld_node && (strcmp(node[i]->element, osalerts) == 0)) {
            if ((modules & CALERTS) && (Read_Alerts(chld_node, d1, d2, output) < 0)) {
                goto fail;
            }
        } else if (chld_node && (strcmp(node[i]->element, oslocalfile) == 0)) {
            if ((modules & CLOCALFILE) && (Read_Localfile(chld_node, d1, d2, output) < 0)) {
                goto fail;
            }
        } else if (chld_node && (strcmp(node[i]->element, osremote) == 0)) {
            if ((modules & CREMOTE) && (Read_Remote(chld_node, d1, d2, output) < 0)) {
                goto fail;
            }
        } else if (chld_node && (strcmp(node[i]->element, osclient) == 0)) {
            if ((modules & CCLIENT) && (Read_Client(xml, chld_node, d1, d2, output) < 0)) {
                goto fail;
            }
        } else if (strcmp(node[i]->element, osbuffer) == 0) {
            if ((modules & CBUFFER) && (Read_ClientBuffer(chld_node, d1, d2, output) < 0)) {
                goto fail;
            }
        } else if (chld_node && (strcmp(node[i]->element, oscommand) == 0)) {
            if ((modules & CAR) && (ReadActiveCommands(chld_node, d1, d2, output) < 0)) {
                goto fail;
            }
        } else if (chld_node && (strcmp(node[i]->element, osactive_response) == 0)) {
            if ((modules & CAR) && (ReadActiveResponses(chld_node, d1, d2, output) < 0)) {
                goto fail;
            }
        } else if (chld_node && (strcmp(node[i]->element, osreports) == 0)) {
            if ((modules & CREPORTS) && (Read_CReports(chld_node, d1, d2, output) < 0)) {
                goto fail;
            }
        } else if (strcmp(node[i]->element, oswmodule) == 0) {
            const int cfg_type = modules & CAGENT_CGFILE ? CAGENT_CGFILE : (modules & CRMOTE_CONFIG ? CRMOTE_CONFIG : 0);
            if ((modules & CWMODULE) && (Read_WModule(xml, node[i], d1, d2, cfg_type, output) < 0)) {
                goto fail;
            }
        } else if (strcmp(node[i]->element, ossca) == 0) {
            if ((modules & CWMODULE) && (Read_SCA(xml, node[i], d1, output) < 0)) {
                goto fail;
            }
        } else if (strcmp(node[i]->element, osvulndet) == 0) {
#if !defined(WIN32) && !defined(CLIENT)
            if ((modules & CWMODULE) && (Read_Vuln(xml, chld_node, d1, 1) < 0)) {
                goto fail;
            }
#else
            mwarn("%s configuration is only set in the manager.", node[i]->element);
#endif
        }
#ifndef WIN32
        else if (strcmp(node[i]->element, osfluent_forward) == 0) {
            if ((modules & CWMODULE) && !(modules & CRMOTE_CONFIG) && (Read_Fluent_Forwarder(xml, node[i], d1, output) < 0)) {
                goto fail;
            }
        }
#endif
        else if (chld_node && (strcmp(node[i]->element, oslabels) == 0)) {
            if ((modules & CLABELS) && (Read_Labels(chld_node, d1, d2, output) < 0)) {
                goto fail;
            }
        } else if (strcmp(node[i]->element, osauthd) == 0) {
            if ((modules & CAUTHD) && (Read_Authd(chld_node, d1, d2, output) < 0)) {
                goto fail;
            }
        } else if (strcmp(node[i]->element, oslogging) == 0) {
        } else if (chld_node && (strcmp(node[i]->element, oscluster) == 0)) {
            if ((modules & CCLUSTER) && (Read_Cluster(xml, chld_node, d1, d2, output) < 0)) {
                goto fail;
            }
        } else if (chld_node && (strcmp(node[i]->element, ossocket) == 0)) {
            if ((modules & CSOCKET) && (Read_Socket(chld_node, d1, d2, output) < 0)) {
                goto fail;
            }
        } else if (output == NULL){
            merror(XML_INVELEM, node[i]->element);
            goto fail;
        } else {
            char message[OS_FLSIZE];
            snprintf(message, OS_FLSIZE + 1,
                "Invalid element in the configuration: '%s'.", node[i]->element);
            wm_strcat(output, message, '\n');
            goto fail;
        }

        OS_ClearNode(chld_node);
        i++;

        continue;

        fail:
        OS_ClearNode(chld_node);
        return (OS_INVALID);
    }

    return (0);
}

/* Read the config files */
int ReadConfig(int modules, const char *cfgfile, void *d1, void *d2, char **output)
{
    int i;
    OS_XML xml;
    XML_NODE node;
    char message[OS_FLSIZE];

    /** XML definitions **/
    /* Global */
    const char *xml_start_ossec = "ossec_config";
    const char *xml_start_agent = "agent_config";

    /* Attributes of the <agent_config> tag */
    const char *xml_agent_name = "name";
    const char *xml_agent_os = "os";
    const char *xml_agent_overwrite = "overwrite";
    const char *xml_agent_profile = "profile";

    if ((modules & CRMOTE_CONFIG) && !getDefine_Int("agent", "remote_conf", 0, 1)) {
      return 0;
    }

    if (OS_ReadXML(cfgfile, &xml) < 0) {
        if (modules & CRMOTE_CONFIG) {
#ifndef CLIENT
            if (output == NULL){
                merror(XML_ERROR, cfgfile, xml.err, xml.err_line);
            } else {
                snprintf(message, OS_FLSIZE + 1,
                    "Error reading XML file '%s': %s (line %d).", cfgfile, xml.err, xml.err_line);
                wm_strcat(output, message, '\n');
            }
#endif
        } else if (output == NULL){
            merror(XML_ERROR, cfgfile, xml.err, xml.err_line);
        } else {
            snprintf(message, OS_FLSIZE + 1,
                "Error reading XML file '%s': %s (line %d).", cfgfile, xml.err, xml.err_line);
            wm_strcat(output, message, '\n');
        }
        return (OS_INVALID);
    }

    node = OS_GetElementsbyNode(&xml, NULL);
    if (!node) {
        return (0);
    }

    /* Read the main configuration */
    i = 0;
    while (node[i]) {
        if (!node[i]->element) {
            if (output == NULL){
                merror(XML_ELEMNULL);
            } else {
                wm_strcat(output, "Invalid NULL in the configuration", '\n');
            }
            OS_ClearNode(node);
            OS_ClearXML(&xml);
            return (OS_INVALID);
        } else if (!(modules & CRMOTE_CONFIG) &&
                   (strcmp(node[i]->element, xml_start_ossec) == 0)) {
            XML_NODE chld_node = NULL;
            chld_node = OS_GetElementsbyNode(&xml, node[i]);

            /* Main element does not need to have any child */
            if (chld_node) {
                if (read_main_elements(&xml, modules, chld_node, d1, d2, output) < 0) {
                    if (output == NULL){
                        merror(CONFIG_ERROR, cfgfile);
                    } else {
                        snprintf(message, OS_FLSIZE + 1,
                            "Configuration error at '%s'.", cfgfile);
                        wm_strcat(output, message, '\n');
                    }
                    OS_ClearNode(chld_node);
                    OS_ClearNode(node);
                    OS_ClearXML(&xml);
                    return (OS_INVALID);
                }

                OS_ClearNode(chld_node);
            }
        } else if ((modules & CRMOTE_CONFIG) &&
                   (strcmp(node[i]->element, xml_start_agent) == 0)) {
            int passed_agent_test = 1;
            int attrs = 0;
            XML_NODE chld_node = NULL;
            chld_node = OS_GetElementsbyNode(&xml, node[i]);

            /* Check if this is specific to any agent */
            if (node[i]->attributes && node[i]->values) {
                while (node[i]->attributes[attrs] && node[i]->values[attrs]) {
                    /* Check if there is an "name=" attribute */
                    if (strcmp(xml_agent_name, node[i]->attributes[attrs]) == 0) {
#ifdef CLIENT
                        char *agentname = os_read_agent_name();

                        if (!agentname) {
                            passed_agent_test = 0;
                            if (output == NULL){
                                merror("Reading shared configuration. Unable to retrieve the agent name.");
                            } else {
                                wm_strcat(output, "Reading shared configuration. Unable to retrive the agent name", '\n');
                            }
                        } else if (strlen(node[i]->values[attrs]) > OS_PATTERN_MAXSIZE) {
                            int attrlen = strlen(node[i]->values[attrs]);
                            if (output == NULL){
                                mwarn("Agent name filter (%d bytes) exceeds the limit (%d)", attrlen, OS_PATTERN_MAXSIZE);
                            } else {
                                snprintf(message, OS_FLSIZE + 1
                                    "WARNING: Agent name filter (%d bytes) exceeds the limit (%d)", 
                                    attrlen, OS_PATTERN_MAXSIZE);
                                wm_strcat(output, message, '\n');
                            }
                            passed_agent_test = 0;
                            free(agentname);
                        } else {
                            if (!OS_Match2(node[i]->values[attrs], agentname)) {
                                passed_agent_test = 0;
                            }
                            free(agentname);
                        }
#endif
                    } else if (strcmp(xml_agent_os, node[i]->attributes[attrs]) == 0) {
#ifdef CLIENT
                        const char *agentos = getuname();

                        if (!agentos) {
                            passed_agent_test = 0;
                            if (output == NULL){
                                merror("Reading shared configuration. Unable to retrieve the agent OS.");
                            } else {
                                wm_strcat(output, "Reading shared configuration. Unable to retrive the agent OS", '\n');
                            }
                        } else if (strlen(node[i]->values[attrs]) > OS_PATTERN_MAXSIZE) {
                            int attrlen = strlen(node[i]->values[attrs]);
                            if (output = NULL){
                                mwarn("Agent OS filter (%d bytes) exceeds the limit (%d)", attrlen, OS_PATTERN_MAXSIZE);
                            } else {
                                snprintf(message, OS_FLSIZE + 1,
                                    "WARNING: Agent OS filter (%d bytes) exceeds the limit (%d)", 
                                    attrlen, OS_PATTERN_MAXSIZE);
                                wm_strcat(output, message, '\n');
                            }
                            passed_agent_test = 0;
                        } else if (!OS_Match2(node[i]->values[attrs], agentos)) {
                            passed_agent_test = 0;
                        }
#endif
                    } else if (strcmp(xml_agent_profile, node[i]->attributes[attrs]) == 0) {
#ifdef CLIENT
                        char *agentprofile = os_read_agent_profile();

                        if (!agentprofile) {
                            passed_agent_test = 0;
                            if (output == NULL){
                                merror("Reading shared configuration. Unable to retrieve agent profile.");
                            } else {
                                wm_strcat(output, "Reading shared configuration. Unable to retrive the agent profile", '\n');
                            }
                        } else if (strlen(node[i]->values[attrs]) > OS_PATTERN_MAXSIZE) {
                            int attrlen = strlen(node[i]->values[attrs]);
                            if (output == NULL){
                                mwarn("Agent profile filter (%d bytes) exceeds the limit (%d)", attrlen, OS_PATTERN_MAXSIZE);
                            } else {
                                snprintf(message, OS_FLSIZE + 1,
                                    "WARNING: Agent profile filter (%d bytes) exceeds the limit (%d)", 
                                    attrlen, OS_PATTERN_MAXSIZE);
                                wm_strcat(output, message, '\n');
                            }
                            passed_agent_test = 0;
                            free(agentprofile);
                        } else {
                            /* match the profile name of this <agent_config> section
                             * with a comma separated list of values in agent's
                             * <config-profile> tag.
                             */
                            if (!OS_Match2(node[i]->values[attrs], agentprofile)) {
                                passed_agent_test = 0;
                                if (output == NULL){
                                    mdebug2("[%s] did not match agent config profile name [%s]",
                                       node[i]->values[attrs], agentprofile);
                                }
                            } else if (output == NULL){
                                mdebug2("Matched agent config profile name [%s]", agentprofile);
                            }
                            free(agentprofile);
                        }
#endif
                    } else if (strcmp(xml_agent_overwrite, node[i]->attributes[attrs]) == 0) {
                    } else {
                        if (output == NULL){
                            merror(XML_INVATTR, node[i]->attributes[attrs], cfgfile);
                        } else {
                            snprintf(message, OS_FLSIZE + 1,
                                "Configuration error at '%s'.", cfgfile);
                            wm_strcat(output, message, '\n');
                        }
#ifndef CLIENT
                        OS_ClearNode(chld_node);
                        OS_ClearNode(node);
                        OS_ClearXML(&xml);
                        return (OS_INVALID);
#endif
                    }
                    attrs++;
                }
            }
#ifdef CLIENT
            else {
                char *agentprofile = os_read_agent_profile();
                if (output == NULL){
                    mdebug2("agent_config element does not have any attributes.");
                }
                
                /* if node does not have any attributes, it is a generic config block.
                 * check if agent has a profile name
                 * if agent does not have profile name, then only read this generic
                 * agent_config block
                 */

                if (!agentprofile) {
                    if (output == NULL) {
                        mdebug2("but agent has a profile name.");
                    }
                    passed_agent_test = 0;
                } else {
                    free(agentprofile);
                }
            }
#endif

            /* Main element does not need to have any child */
            if (chld_node) {
                if (passed_agent_test && read_main_elements(&xml, modules, chld_node, d1, d2, output) < 0) {
                    if (output == NULL){
                        merror(CONFIG_ERROR, cfgfile);
                    } else {
                        snprintf(message, OS_FLSIZE + 1,
                            "Configuration error at '%s'.", cfgfile);
                        wm_strcat(output, message, '\n');
                    }
                    OS_ClearNode(chld_node);
                    OS_ClearNode(node);
                    OS_ClearXML(&xml);
                    return (OS_INVALID);
                }

                OS_ClearNode(chld_node);
            }
        } else {
            if (output == NULL){
                merror(XML_INVELEM, node[i]->element);
            } else {
                snprintf(message, OS_FLSIZE + 1,
                    "Invalid elemente in the configuration: '%s'.",
                    node[i]->element);
                wm_strcat(output, message, '\n');
            } 
            OS_ClearNode(node);
            OS_ClearXML(&xml);
            return (OS_INVALID);
        }
        i++;
    }

    /* Clear node and xml */
    OS_ClearNode(node);
    OS_ClearXML(&xml);
    return (0);
}

int Test_Analysisd(const char *path, char **output) {
    int fail = 0;
    _Config *test_config;
    os_calloc(1, sizeof(_Config), test_config);

    int modules = CGLOBAL | CRULES | CALERTS | CCLUSTER;
    if( (ReadConfig(modules, path, test_config, NULL, output) < 0) || (ReadConfig(CLABELS, path, &(test_config->labels), NULL, output) < 0) ) {
        if (output == NULL){
            merror(CONF_READ_ERROR, "Analysisd");
        } else {
            wm_strcat(output, "ERROR: Invalid configuration in Analysisd", '\n');
        }
        fail = 1;
    }

    if(!fail) {
        test_config->min_rotate_interval = getDefine_Int("analysisd", "min_rotate_interval", 10, 86400);

        if (test_config->rotate_interval && (test_config->rotate_interval < test_config->min_rotate_interval || test_config->rotate_interval > 86400)) {
            if (output == NULL){
                merror("Rotate interval setting must be between %d seconds and one day.", test_config->min_rotate_interval);
            } else {
                wm_strcat(output, "ERROR: Invalid configuration in Analysisd", '\n');
            }
            fail = 1;
        }

        if (!fail && test_config->max_output_size && (test_config->max_output_size < 1000000 || test_config->max_output_size > 1099511627776)) {
            if (output == NULL){
                merror("Maximum output size must be between 1 MiB and 1 TiB.");
            } else {
                wm_strcat(output, "Maximum output size must be between 1 MiB and 1 TiB.", '\n');
            }
            fail = 1;
        }
    }

    /* Free memory */
    config_free(test_config);

    if (output) {
        free(test_config);
    }

    if(fail) {
        return OS_INVALID;
    }

    return 0;
}
