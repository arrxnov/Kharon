import json
from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
from mythic_container.PayloadBuilder import *

from .Utils.u import *

class KrbGenericArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            self.add_arg(
                CommandParameter(
                    name="input",
                    type=ParameterType.String,
                    description="kerbeus entry",
                    default_value=self.command_line
                )
            )
class KrbAsrepRoastingCommand(CommandBase):
    cmd = "krb-asreproasting"
    needs_admin = False
    help_cmd = "krb-asreproasting /user:USER [/dc:DC] [/domain:DOMAIN]"
    description = "Perform AS-REP roasting attack."
    version = 1
    author = "@Oblivion"
    argument_class = KrbGenericArguments

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        content: bytes = await get_content_by_name("kh_krb-asreproasting.x64.o", task.Task.ID)
        input_str = task.args.get_arg("input") or ""
        bof_args = [{"type": "char", "value": input_str}]
        task.args.remove_arg("input")
        task.args.add_arg("bof_file", content.hex())
        task.args.add_arg("bof_id", 0, ParameterType.Number)
        task.args.add_arg("bof_args", json.dumps(bof_args))
        return PTTaskCreateTaskingMessageResponse(TaskID=task.Task.ID, CommandName="exec-bof", TokenID=task.Task.TokenID, DisplayParams=input_str)

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp



class KrbAskTgtCommand(CommandBase):
    cmd = "krb-asktgt"
    needs_admin = False
    help_cmd = "krb-asktgt /user:USER /password:PASSWORD [/domain:DOMAIN] [/dc:DC]"
    description = "Retrieve a TGT using username, password, or hash."
    version = 1
    author = "@Oblivion"
    argument_class = KrbGenericArguments

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        content: bytes = await get_content_by_name("kh_krb-asktgt.x64.o", task.Task.ID)
        input_str = task.args.get_arg("input") or ""
        bof_args = [{"type": "char", "value": input_str}]
        task.args.remove_arg("input")
        task.args.add_arg("bof_file", content.hex())
        task.args.add_arg("bof_id", 0, ParameterType.Number)
        task.args.add_arg("bof_args", json.dumps(bof_args))
        return PTTaskCreateTaskingMessageResponse(TaskID=task.Task.ID, CommandName="exec-bof", TokenID=task.Task.TokenID, DisplayParams=input_str)

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp



class KrbAskTgsCommand(CommandBase):
    cmd = "krb-asktgs"
    needs_admin = False
    help_cmd = "krb-asktgs /ticket:BASE64 /service:SPN"
    description = "Retrieve a TGS ticket."
    version = 1
    author = "@Oblivion"
    argument_class = KrbGenericArguments

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        content: bytes = await get_content_by_name("kh_krb-asktgs.x64.o", task.Task.ID)
        input_str = task.args.get_arg("input") or ""
        bof_args = [{"type": "char", "value": input_str}]
        task.args.remove_arg("input")
        task.args.add_arg("bof_file", content.hex())
        task.args.add_arg("bof_id", 0, ParameterType.Number)
        task.args.add_arg("bof_args", json.dumps(bof_args))
        return PTTaskCreateTaskingMessageResponse(TaskID=task.Task.ID, CommandName="exec-bof", TokenID=task.Task.TokenID, DisplayParams=input_str)

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp



class KrbChangePwCommand(CommandBase):
    cmd = "krb-changepw"
    needs_admin = False
    help_cmd = "krb-changepw /ticket:BASE64 /new:PASSWORD"
    description = "Reset a user's password using a supplied TGT."
    version = 1
    author = "@Oblivion"
    argument_class = KrbGenericArguments

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        content: bytes = await get_content_by_name("kh_krb-changepw.x64.o", task.Task.ID)
        input_str = task.args.get_arg("input") or ""
        bof_args = [{"type": "char", "value": input_str}]
        task.args.remove_arg("input")
        task.args.add_arg("bof_file", content.hex())
        task.args.add_arg("bof_id", 0, ParameterType.Number)
        task.args.add_arg("bof_args", json.dumps(bof_args))
        return PTTaskCreateTaskingMessageResponse(TaskID=task.Task.ID, CommandName="exec-bof", TokenID=task.Task.TokenID, DisplayParams=input_str)

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp



class KrbDescribeCommand(CommandBase):
    cmd = "krb-describe"
    needs_admin = False
    help_cmd = "krb-describe /ticket:BASE64"
    description = "Parse and describe a Kerberos ticket."
    version = 1
    author = "@Oblivion"
    argument_class = KrbGenericArguments

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        content: bytes = await get_content_by_name("kh_krb-describe.x64.o", task.Task.ID)
        input_str = task.args.get_arg("input") or ""
        bof_args = [{"type": "char", "value": input_str}]
        task.args.remove_arg("input")
        task.args.add_arg("bof_file", content.hex())
        task.args.add_arg("bof_id", 0, ParameterType.Number)
        task.args.add_arg("bof_args", json.dumps(bof_args))
        return PTTaskCreateTaskingMessageResponse(TaskID=task.Task.ID, CommandName="exec-bof", TokenID=task.Task.TokenID, DisplayParams=input_str)

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp



class KrbDumpCommand(CommandBase):
    cmd = "krb-dump"
    needs_admin = False
    help_cmd = "krb-dump [/luid:LOGINID] [/user:USER] ..."
    description = "Dump Kerberos tickets from memory."
    version = 1
    author = "@Oblivion"
    argument_class = KrbGenericArguments

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        content: bytes = await get_content_by_name("kh_krb-dump.x64.o", task.Task.ID)
        input_str = task.args.get_arg("input") or ""
        bof_args = [{"type": "char", "value": input_str}]
        task.args.remove_arg("input")
        task.args.add_arg("bof_file", content.hex())
        task.args.add_arg("bof_id", 0, ParameterType.Number)
        task.args.add_arg("bof_args", json.dumps(bof_args))
        return PTTaskCreateTaskingMessageResponse(TaskID=task.Task.ID, CommandName="exec-bof", TokenID=task.Task.TokenID, DisplayParams=input_str)

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp



class KrbHashCommand(CommandBase):
    cmd = "krb-hash"
    needs_admin = False
    help_cmd = "krb-hash /password:PASSWORD [/user:USER] [/domain:DOMAIN]"
    description = "Calculate Kerberos key hashes (rc4/aes128/aes256)."
    version = 1
    author = "@Oblivion"
    argument_class = KrbGenericArguments

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        content: bytes = await get_content_by_name("kh_krb-hash.x64.o", task.Task.ID)
        input_str = task.args.get_arg("input") or ""
        bof_args = [{"type": "char", "value": input_str}]
        task.args.remove_arg("input")
        task.args.add_arg("bof_file", content.hex())
        task.args.add_arg("bof_id", 0, ParameterType.Number)
        task.args.add_arg("bof_args", json.dumps(bof_args))
        return PTTaskCreateTaskingMessageResponse(TaskID=task.Task.ID, CommandName="exec-bof", TokenID=task.Task.TokenID, DisplayParams=input_str)

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp



class KrbKerberoastingCommand(CommandBase):
    cmd = "krb-kerberoasting"
    needs_admin = False
    help_cmd = "krb-kerberoasting /spn:SPN [/nopreauth:USER] [/dc:DC] [/domain:DOMAIN]\nkrb-kerberoasting /spn:SPN /ticket:BASE64 [/dc:DC]"
    description = "Perform Kerberoasting attack."
    version = 1
    author = "@Oblivion"
    argument_class = KrbGenericArguments

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        content: bytes = await get_content_by_name("kh_krb-kerberoasting.x64.o", task.Task.ID)
        input_str = task.args.get_arg("input") or ""
        bof_args = [{"type": "char", "value": input_str}]
        task.args.remove_arg("input")
        task.args.add_arg("bof_file", content.hex())
        task.args.add_arg("bof_id", 0, ParameterType.Number)
        task.args.add_arg("bof_args", json.dumps(bof_args))
        return PTTaskCreateTaskingMessageResponse(TaskID=task.Task.ID, CommandName="exec-bof", TokenID=task.Task.TokenID, DisplayParams=input_str)

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp



class KrbKlistCommand(CommandBase):
    cmd = "krb-klist"
    needs_admin = False
    help_cmd = "krb-klist [/luid:LOGINID] ..."
    description = "List Kerberos tickets."
    version = 1
    author = "@Oblivion"
    argument_class = KrbGenericArguments

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        content: bytes = await get_content_by_name("kh_krb-klist.x64.o", task.Task.ID)
        input_str = task.args.get_arg("input") or ""
        bof_args = [{"type": "char", "value": input_str}]
        task.args.remove_arg("input")
        task.args.add_arg("bof_file", content.hex())
        task.args.add_arg("bof_id", 0, ParameterType.Number)
        task.args.add_arg("bof_args", json.dumps(bof_args))
        return PTTaskCreateTaskingMessageResponse(TaskID=task.Task.ID, CommandName="exec-bof", TokenID=task.Task.TokenID, DisplayParams=input_str)

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp



class KrbPttCommand(CommandBase):
    cmd = "krb-ptt"
    needs_admin = False
    help_cmd = "krb-ptt /ticket:BASE64 [/luid:LOGONID]"
    description = "Pass-the-Ticket: inject Kerberos TGT."
    version = 1
    author = "@Oblivion"
    argument_class = KrbGenericArguments

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        content: bytes = await get_content_by_name("kh_krb-ptt.x64.o", task.Task.ID)
        input_str = task.args.get_arg("input") or ""
        bof_args = [{"type": "char", "value": input_str}]
        task.args.remove_arg("input")
        task.args.add_arg("bof_file", content.hex())
        task.args.add_arg("bof_id", 0, ParameterType.Number)
        task.args.add_arg("bof_args", json.dumps(bof_args))
        return PTTaskCreateTaskingMessageResponse(TaskID=task.Task.ID, CommandName="exec-bof", TokenID=task.Task.TokenID, DisplayParams=input_str)

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp



class KrbPurgeCommand(CommandBase):
    cmd = "krb-purge"
    needs_admin = False
    help_cmd = "krb-purge [/luid:LOGONID]"
    description = "Purge Kerberos tickets."
    version = 1
    author = "@Oblivion"
    argument_class = KrbGenericArguments

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        content: bytes = await get_content_by_name("kh_krb-purge.x64.o", task.Task.ID)
        input_str = task.args.get_arg("input") or ""
        bof_args = [{"type": "char", "value": input_str}]
        task.args.remove_arg("input")
        task.args.add_arg("bof_file", content.hex())
        task.args.add_arg("bof_id", 0, ParameterType.Number)
        task.args.add_arg("bof_args", json.dumps(bof_args))
        return PTTaskCreateTaskingMessageResponse(TaskID=task.Task.ID, CommandName="exec-bof", TokenID=task.Task.TokenID, DisplayParams=input_str)

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp



class KrbRenewCommand(CommandBase):
    cmd = "krb-renew"
    needs_admin = False
    help_cmd = "krb-renew /ticket:BASE64 [/dc:DC] [/ptt]"
    description = "Renew a Kerberos TGT."
    version = 1
    author = "@Oblivion"
    argument_class = KrbGenericArguments

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        content: bytes = await get_content_by_name("kh_krb-renew.x64.o", task.Task.ID)
        input_str = task.args.get_arg("input") or ""
        bof_args = [{"type": "char", "value": input_str}]
        task.args.remove_arg("input")
        task.args.add_arg("bof_file", content.hex())
        task.args.add_arg("bof_id", 0, ParameterType.Number)
        task.args.add_arg("bof_args", json.dumps(bof_args))
        return PTTaskCreateTaskingMessageResponse(TaskID=task.Task.ID, CommandName="exec-bof", TokenID=task.Task.TokenID, DisplayParams=input_str)

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp



class KrbS4uCommand(CommandBase):
    cmd = "krb-s4u"
    needs_admin = False
    help_cmd = "krb-s4u /ticket:BASE64 /service:SPN ..."
    description = "Perform S4U constrained delegation abuse."
    version = 1
    author = "@Oblivion"
    argument_class = KrbGenericArguments

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        content: bytes = await get_content_by_name("kh_krb-s4u.x64.o", task.Task.ID)
        input_str = task.args.get_arg("input") or ""
        bof_args = [{"type": "char", "value": input_str}]
        task.args.remove_arg("input")
        task.args.add_arg("bof_file", content.hex())
        task.args.add_arg("bof_id", 0, ParameterType.Number)
        task.args.add_arg("bof_args", json.dumps(bof_args))
        return PTTaskCreateTaskingMessageResponse(TaskID=task.Task.ID, CommandName="exec-bof", TokenID=task.Task.TokenID, DisplayParams=input_str)

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp



class KrbCrossS4uCommand(CommandBase):
    cmd = "krb-cross-s4u"
    needs_admin = False
    help_cmd = "krb-cross-s4u /ticket:BASE64 /service:SPN /targetdomain:DOMAIN"
    description = "Perform S4U constrained delegation abuse across domains."
    version = 1
    author = "@Oblivion"
    argument_class = KrbGenericArguments

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        content: bytes = await get_content_by_name("kh_krb-cross_s4u.x64.o", task.Task.ID)
        input_str = task.args.get_arg("input") or ""
        bof_args = [{"type": "char", "value": input_str}]
        task.args.remove_arg("input")
        task.args.add_arg("bof_file", content.hex())
        task.args.add_arg("bof_id", 0, ParameterType.Number)
        task.args.add_arg("bof_args", json.dumps(bof_args))
        return PTTaskCreateTaskingMessageResponse(TaskID=task.Task.ID, CommandName="exec-bof", TokenID=task.Task.TokenID, DisplayParams=input_str)

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp



class KrbTgtDelegCommand(CommandBase):
    cmd = "krb-tgtdeleg"
    needs_admin = False
    help_cmd = "krb-tgtdeleg [/target:SPN]"
    description = "Abuse Kerberos GSS-API to get a usable TGT without elevation."
    version = 1
    author = "@Oblivion"
    argument_class = KrbGenericArguments

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        content: bytes = await get_content_by_name("kh_krb-tgtdeleg.x64.o", task.Task.ID)
        input_str = task.args.get_arg("input") or ""
        bof_args = [{"type": "char", "value": input_str}]
        task.args.remove_arg("input")
        task.args.add_arg("bof_file", content.hex())
        task.args.add_arg("bof_id", 0, ParameterType.Number)
        task.args.add_arg("bof_args", json.dumps(bof_args))
        return PTTaskCreateTaskingMessageResponse(TaskID=task.Task.ID, CommandName="exec-bof", TokenID=task.Task.TokenID, DisplayParams=input_str)

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp

    

