import argparse
from typing import List, Optional, Tuple

from outflank_stage1.task.base_bof_task import BaseBOFTask
from outflank_stage1.task.enums import BOFArgumentEncoding, BOFType
from outflank_stage1.implant.enums import ImplantArch, ImplantPrivilege, ImplantOSType
from outflank_stage1.task.exceptions import TaskException, TaskInvalidArgumentsException

CONVERSION_TABLE = {
    "Base": 1,
    "OneLevel": 2,
    "Subtree": 3
}

class LDAPSearchAsyncBOF(BaseBOFTask):
    def __init__(self):
        super().__init__("ldapsearch_nw", base_binary_name="ldapsearch")

        self.parser.add_argument("query", help="The query to perform.")

        self.parser.add_argument(
            "attributes",
            default="*,ntSecurityDescriptor",
            help='Comma seperated attributes ("" = all) (default = "*,ntSecurityDescriptor").',
            nargs="?",
        )

        self.parser.add_argument(
            "--result_count",
            default=0,
            help="The maximum number of results (0 = no limit).",
            type=int,
        )

        self.parser.add_argument(
            "--scope",
            choices=CONVERSION_TABLE.keys(),
            default="Subtree",
            help="Search scope.",
        )

        self.parser.add_argument("--dc", default="", help='DC hostname or IP ("" = default).')

        self.parser.add_argument(
            "--dn",
            default="",
            help='Distinguished Name to use ("" = default).',
        )

        self.parser.add_argument(
            "--ldaps", 
            action='store_true',
            default=False,
            help='Use LDAPS'
        )

        self.parser.description = "Perform LDAP search."

        self.parser.epilog = (
            "Note: If this fails with an error about paging not being supported you can try to use nonpagedldapsearch "
            "instead (it has the same arguments).\n\n"
            "Example usage:\n"
            "  - Query single user/pc/group:\n"
            "    ldapsearch_nw (samAccountName=COMPUTERNAME_OR_USERNAME$)\n"
            "  - Query AS-REP roastable users:\n"
            "    ldapsearch_nw (&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))\n"
            "\n"
            "Important - To add in ACLs so Bloodhound can draw relationships between objects (see external BofHound tool), ensure nTSecurityDescriptor in the attributes list (which it is by default), like so:\n"
            "ldapsearch_nw <query> *,ntsecuritydescriptor"
        )

    def split_arguments(self, arguments: Optional[str], strip_quotes: bool = False) -> List[str]:
        return super().split_arguments(arguments, True)

    def _encode_arguments_bof(self, arguments: List[str]) -> List[Tuple[BOFArgumentEncoding, str]]:
        parser_arguments = self.parser.parse_args(arguments)

        return [
            (BOFArgumentEncoding.STR, parser_arguments.query),
            (BOFArgumentEncoding.STR, parser_arguments.attributes),
            (BOFArgumentEncoding.INT, parser_arguments.result_count),
            (BOFArgumentEncoding.INT, CONVERSION_TABLE[parser_arguments.scope]),
            (BOFArgumentEncoding.STR, parser_arguments.dc),
            (BOFArgumentEncoding.STR, parser_arguments.dn),
            (BOFArgumentEncoding.INT, int(parser_arguments.ldaps)),
        ]
