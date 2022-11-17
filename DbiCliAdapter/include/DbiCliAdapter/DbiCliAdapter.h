#ifndef DBICLIADAPTER_H
#define DBICLIADAPTER_H

#include <string>
#include <vector>
#include "OsIf/DbiServer/OsIfDbiServerStdCmd.h"
#include "OsIf/DbiServer/OsIfDbiServerStdCmdInfo.h"
#include "OsIf/DbiServer/OsIfDbiServer.h"

/**
 * @class DbiCliAdapter
 * @brief Enables the interface with DBI client by registering commands structured in directories.
 * USAGE:
 * To enable this functionality, each SW component that need to provide DBI cli commands need to inherit from this class
 * and pass to the DbiCliAdapter constructor the Command Menu (see DbiCliCmd, DbiCliCmdDirectory)
 *
 * Let's take short example for FmAgent that need to provide 2xcommands:
 * 1) list active faults
 * 2) list inactive faults
 *
 * ------------
 * Code Sample
 * ------------
 *
 * (Class definition)
 * class FmAgent : public DbiCliAdapter
 * (...)
 *
 * (Implementation)
 *
 * DBI CLI MENU
 *  const std::vector<DbiCliAdapter::DbiCliCmdDirectory> FmAgent::DbiCommandMenu =
 *   boost::assign::list_of
 *       (
 *           DbiCliAdapter::DbiCliCmdDirectory("fault", "Fault utils",
 *                                      boost::assign::list_of
 *                                           (DbiCliAdapter::DbiCliCmd("active", "list ACTIVE faults", 0, 0, ""))
 *                                           (DbiCliAdapter::DbiCliCmd("inactive", "list ACTIVE faults", 0, 0, "")
 *           )
 *       )
 *
 * FmAgent:FmAgent()
 * : DbiCliAdapter("fmagent_1", "Fm Agent dbi commands", DbiCommandMenu)
 * (...)
 *
 *
 * Now from dbiClient App, under FmAgent dbi server, you will find available new the dbi directory:
 *
 * [/dbi/fm-agent-1-1]dbi->help

 * DIRECTORIES
 * -----------
 * logTo                       -- LogTo manager commands
 * fmagent_1                   -- Fm Agent dbi commands
 * dm                          -- Data Model commands
 * nucleus                     -- Nucleus Data Model
 * dm2dm                       -- Dm2Dm utilities
 * BasefmAgent                 -- PROCESS DBI interface
 *
 *
 * [/dbi/fm-agent-1-1]dbi->fmagent_1.fault
 *
 * COMMANDS OF [fmagent_1.fault]
 * -----------
 * fmagent_1.fault.active           -- list Active faults
 * fmagent_1.fault.inactive         -- list Inactive faults
 *
 */
class DbiCliAdapter
{
    public:
        /**
         * @brief Structure that represents a DBI command
         */
        struct DbiCliCmd
        {
            std::string name;
            std::string description;
            int minArgs;
            int maxArgs;
            std::string paramDescription;

            DbiCliCmd(std::string pName, std::string pDescription, int pMinArgs, int pMaxArgs,
                      std::string pParamDescription)
                : name(pName)
                , description(pDescription)
                , minArgs(pMinArgs)
                , maxArgs(pMaxArgs)
                , paramDescription(pParamDescription)
            {}
        };

        /**
         * @brief Structure that represents a DBI directory (group of commands)
         */
        struct DbiCliCmdDirectory
        {
            std::string name;
            std::string description;
            std::vector<DbiCliCmd> commandList;

            DbiCliCmdDirectory(std::string pName, std::string pDescription, std::vector<DbiCliCmd> pCommandList)
                : name(pName)
                , description(pDescription)
            {
                commandList.swap(pCommandList);
            }
        };

        /**
         * @brief Default contructor
         */
        DbiCliAdapter() = default;

        /**
         * @brief Custom constructor
         * @param dbiApplicationName DBI application menu name
         * @param dbiApplicationDescription DBI application description
         * @param dbiMenu The DBI command menu
         */
        DbiCliAdapter(const std::string& dbiApplicationName, const std::string& dbiApplicationDescription,
                      const std::vector<DbiCliCmdDirectory>& dbiMenu);

        /**
         * @brief Default destructor
         */
        virtual ~DbiCliAdapter() = default;

        /**
         * @brief Register a command menu on DBI server
         * @param dbiApplicationName DBI application menu name
         * @param dbiApplicationDescription DBI application description
         * @param dbiMenu The DBI command menu
         */
        void registerApplicationDbiMenu(const std::string& dbiApplicationName, const std::string& dbiApplicationDescription,
                                        const std::vector<DbiCliCmdDirectory>& dbiMenu);

        /**
         * @brief Pure virtual function to be implemented by SW component.
         * This will be called whenever a DBI command from the given menu is executed
         * @param cmdInfo command information
         * @param os output stream on DBI console
         */
        virtual void executeCliCommand(osif::dbiserver::StdCmdInfo const& cmdInfo, std::ostream& os) = 0;

        /**
         * @brief Unregister the command menu on DBI server
         * @param dbiApplicationName DBI application menu name
         */
        void unregisterApplicationDbiMenu(const std::string& dbiApplicationName);
};

#endif // DBICLIADAPTER_H

