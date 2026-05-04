import argparse
from typing import List, Tuple, Optional
from outflank_stage1.task.base_bof_task import BaseBOFTask
from outflank_stage1.implant.enums import ImplantArch, ImplantPrivilege
from outflank_stage1.task.enums import BOFArgumentEncoding

class VeeamDumper(BaseBOFTask):
	def __init__(self):
		super().__init__("veeam-dumper",min_privilege=ImplantPrivilege.HIGH,base_binary_name="cs_veeam_dumper")

		self.parser.description = (
			"veeam-dumper [db type] [optional args]"
		)
		self.parser.add_argument(
			"db_type",
			help="mssql, psql, auto",
			# nargs=argparse.REMAINDER,
		)
		self.parser.add_argument(
			"--dbname",
			help="if blank will try pull from registry.",
			default="",
		)
		self.parser.add_argument(
			"--exepath",
			help="Path to sqlcmd.exe/psql.exe. If not specified will search $PATH and common locations depending on the DB type ",
			default="",
		)
		self.parser.add_argument(
			"--debug",
			help="Enables debug output",
			action="store_true",
		)
		self.parser.add_argument(
			"--veeamone",
			help="Run VeeamOne mode",
			action="store_true"
		)
		self.parser.epilog = "Dump credentials from Veeam. Supports PSQL and MSSQL!\n\nUse: veeam-dumper [db type] [optional args]\n\n\t db type (Required):\tmssql, psql, auto \n\t --dbname (Optional):\tif blank will try pull from registry. \n\t --exepath (Optional):\tPath to sqlcmd.exe/psql.exe. If not specified will search \$PATH and common locations depending on the DB type \n\t --debug (Optional):\tEnables debug output\n\t --veeamone (Optional):\tRun VeeamOne mode\n\nExamples:\n\t veeam-dumper auto\n\t veeam-dumper psql --dbname VeeamBackup2016 --exepath \"C:\\Program Files\\pssql.exe\" --debug\n\t veeam-dumper mssql --debug --veeamone"
	
	def _encode_arguments_bof(
		self, arguments: List[str]
	) -> List[Tuple[BOFArgumentEncoding, str]]:
		parser_arguments = self.parser.parse_args(arguments)

		encoded_arguments =  [(BOFArgumentEncoding.STR, parser_arguments.db_type)]
		encoded_arguments.append((BOFArgumentEncoding.STR, parser_arguments.dbname))
		encoded_arguments.append((BOFArgumentEncoding.STR, parser_arguments.exepath))
		if parser_arguments.debug:
			encoded_arguments.append((BOFArgumentEncoding.INT, 1))
		else:
			encoded_arguments.append((BOFArgumentEncoding.INT, 0))
		if parser_arguments.veeamone:   
			encoded_arguments.append((BOFArgumentEncoding.INT, 1))
		else:
			encoded_arguments.append((BOFArgumentEncoding.INT, 0))
		return encoded_arguments

	def validate_arguments(self, arguments: List[str]):
		super().validate_arguments(arguments)
		#  _ = self.parser.parse_args(arguments)
		parser_arguments = self.parser.parse_args(arguments)
		validDbTypes = ["auto","mssql","psql"]
		if (parser_arguments.db_type not in validDbTypes):
			raise TaskInvalidArgumentsException(f"DB type must be auto, mssql or psql. Got {db_type}")


	def run(self, arguments: List[str]):
		self.append_response(
			"Running Veeam Dumper BOF by @MWRCyberSec\n"
		)
		super().run(arguments)
