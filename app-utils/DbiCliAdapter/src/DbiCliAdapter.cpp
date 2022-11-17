#include "DbiCliAdapter/DbiCliAdapter.h"

using osif::dbiserver::StdCmd;

class DbiCmdForwarder: public osif::dbiserver::StdCmdBase
{
    public:
        DbiCmdForwarder(std::string const& name, std::string const& descr,
                        int minArgs, int maxArgs, std::string const& paramDesc,
                        DbiCliAdapter& cmdHandler)
            : StdCmdBase(name, descr, minArgs, maxArgs, paramDesc)
            , myCmdHandler(cmdHandler)
        {}

        void DoCommand(osif::dbiserver::StdCmdInfo const& cmdInfo, std::ostream& os) const override
        {
            // Snapshot stream flags
            std::ios_base::fmtflags snapshotFlags(os.flags());

            try
            {
                myCmdHandler.executeCliCommand(cmdInfo, os);
            }
            catch(const std::exception& e)
            {
                os << "Caught exception in DBI Client application while executing cmd ["
                   << cmdInfo.GetFullCommandWithArgs() << "]! meaning [" << e.what() << "]" << std::endl;
            }
            catch(...)
            {
                os << "Caught unknown exception in DBI Client application while executing cmd ["
                   << cmdInfo.GetFullCommandWithArgs() << "]!" << std::endl;
            }

            // Restore stream flags
            os.flags(snapshotFlags);
        }

    private:
        DbiCliAdapter& myCmdHandler;
};

DbiCliAdapter::DbiCliAdapter(const std::string& dbiApplicationName, const std::string& dbiApplicationDescription,
                             const std::vector<DbiCliCmdDirectory>& dbiMenu)
{
    registerApplicationDbiMenu(dbiApplicationName, dbiApplicationDescription, dbiMenu);
}

void DbiCliAdapter::registerApplicationDbiMenu(const std::string& dbiApplicationName,
                                               const std::string& dbiApplicationDescription,
                                               const std::vector<DbiCliCmdDirectory>& dbiMenu)
{
    auto mainAppDir = std::make_unique<osif::dbiserver::DbiDir>(dbiApplicationName, dbiApplicationDescription);

    for(const DbiCliCmdDirectory& commandDirectory : dbiMenu)
    {
        auto commandDir = std::make_unique<osif::dbiserver::DbiDir>(commandDirectory.name,
                                                                    commandDirectory.description);

        for(const DbiCliCmd& command : commandDirectory.commandList)
        {
            commandDir->AddItem(new DbiCmdForwarder(command.name, command.description,
                                                    command.minArgs, command.maxArgs,
                                                    command.paramDescription, *this));
        }

        mainAppDir->AddItem(commandDir.release());
    }

    // Add main APP dir to root dir
    osif::dbiserver::DbiServer::Instance().GetRootDir().AddItem(mainAppDir.release());
}

void DbiCliAdapter::unregisterApplicationDbiMenu(const std::string& dbiApplicationName)
{
    osif::dbiserver::DbiServer::Instance().GetRootDir().RemoveItem(dbiApplicationName);
}