#!/usr/bin/python

import os,sys
import pefile
import binascii
import hashlib
import argparse
import ssdeep
import textwrap
from argparse import ArgumentParser


class ripPE(object):

	def __init__(self,file_to_rip,dump_mode=False):
		self._dump_mode = dump_mode
		self._filename = file_to_rip
		self._pe = pefile.PE(self._filename)
		#::Begin static stuff::#
		self._pe_compile = self._pe.FILE_HEADER.TimeDateStamp
		self._md5 = hashlib.md5(open(file_to_rip).read()).hexdigest()
		self._ssdeep = ssdeep.hash_from_file(file_to_rip)

	def run_all(self):
		self.list_standard()
		self.dump_iat()
		self.list_imports()
		self.dump_import()
		self.list_exports()
		self.get_virtual_section_info()
		self.get_debug()
		self.get_resource_info()
		self.dump_cert()

	def list_standard(self):
		print "%s,file_md5,file_header,%s" % (self._filename,self._md5)
		print "%s,file_ssdeep,file_header,%s" % (self._filename,self._ssdeep)
		print "%s,timedatestamp,file_header,%s" % (self._filename,self._pe_compile)
	
		version_cat = []
		version_value = []
		version_both = []
		version_list=[]

		for key,value in self._pe.FileInfo[0].StringTable[0].entries.items():
			version_cat.append(key)
			version_value.append(value)
			version_both.append(key + ": " + value)
			print "%s,version_info,file_header_category,%s" % (self._filename,key)
			print "%s,version_info,file_header_value,%s" % (self._filename,value)
			print "%s,version_info,file_header_complete,%s: %s" % (self._filename,key,value)
		
		version_list.append(version_cat)
		version_list.append(version_value)
		version_list.append(version_both)

		version_cat_str = "\n".join(version_list[0])
		version_value_str = "\n".join(version_list[1])
		version_both_str = "\n".join(version_list[2])
		
		print "%s,version_category_md5,file_header_category,%s" % (self._filename,hashlib.md5(version_cat_str.encode('utf-8').strip()).hexdigest())
		print "%s,version_category_ssdeep,file_header_category,%s" % (self._filename,ssdeep.hash(version_cat_str.encode('utf-8').strip()))
		print "%s,version_value_md5,file_header_value,%s" % (self._filename,hashlib.md5(version_value_str.encode('utf-8').strip()).hexdigest())
		print "%s,version_category_ssdeep,file_header_value,%s" % (self._filename,ssdeep.hash(version_value_str.encode('utf-8').strip()))
		print "%s,version_version_md5,file_header_version,%s" % (self._filename,hashlib.md5(version_both_str.encode('utf-8').strip()).hexdigest())
		print "%s,version_version_ssdeep,file_header_value,%s" % (self._filename,ssdeep.hash(version_both_str.encode('utf-8').strip()))

	def dump_import(self):
		if not hasattr(self._pe, 'DIRECTORY_ENTRY_IMPORT'):
			return
		for idx in xrange(len(self._pe.OPTIONAL_HEADER.DATA_DIRECTORY)):
			if self._pe.OPTIONAL_HEADER.DATA_DIRECTORY[idx].name == "IMAGE_DIRECTORY_ENTRY_IMPORT":
				data=self._pe.get_data(self._pe.OPTIONAL_HEADER.DATA_DIRECTORY[idx].VirtualAddress,self._pe.OPTIONAL_HEADER.DATA_DIRECTORY[idx].Size)
				struct_md5=hashlib.md5(data).hexdigest()
				struct_ssdeep=ssdeep.hash(data)
				if self._dump_mode == True:
					write_iat=open("ripPE-IMPORT-" + struct_md5 + "-.import","wb+")
					write_iat.write(data)
					write_iat.close()
				print "%s,import_md5,IMAGE_DIRECTORY_ENTRY_IMPORT,%s" % (self._filename,struct_md5)
				print "%s,import_ssdeep,IMAGE_DIRECTORY_ENTRY_IMPORT,%s" % (self._filename,struct_ssdeep)
	
	def dump_iat(self):
		if not hasattr(self._pe, 'DIRECTORY_ENTRY_DEBUG'):
			return
		for idx in xrange(len(self._pe.OPTIONAL_HEADER.DATA_DIRECTORY)):
			if self._pe.OPTIONAL_HEADER.DATA_DIRECTORY[idx].name == "IMAGE_DIRECTORY_ENTRY_IAT":
				data=self._pe.get_data(self._pe.OPTIONAL_HEADER.DATA_DIRECTORY[idx].VirtualAddress,self._pe.OPTIONAL_HEADER.DATA_DIRECTORY[idx].Size)
				struct_md5=hashlib.md5(data).hexdigest()
				struct_ssdeep=ssdeep.hash(data)
				if self._dump_mode == True:
					write_iat=open("ripPE-" + struct_md5 + "-iat.iat","wb+")
					write_iat.write(data)
					write_iat.close()
				print "%s,iat_md5,IMAGE_DIRECTORY_ENTRY_IAT,%s" % (self._filename,struct_md5)
				print "%s,iat_ssdeep,IMAGE_DIRECTORY_ENTRY_IAT,%s" % (self._filename,struct_ssdeep)

	def list_imports(self):
		#::Bound Imports::#
		if hasattr(self._pe, 'DIRECTORY_ENTRY_BOUND_IMPORT'):
			for entry in self._pe.DIRECTORY_ENTRY_BOUND_IMPORT:
				for imports in entry.entries:
					if (imports.name != None) and (imports.name != ""):
						print "%s,import_symbol,DIRECTORY_ENTRY_IMPORT,%s" % (self._filename,entry.dll + "." + imp.name)

		#::Delayed Imports::#
		if hasattr(self._pe, 'DIRECTORY_ENTRY_DELAY_IMPORT'):
			for module in self._pe.DIRECTORY_ENTRY_DELAY_IMPORT:
				for symbol in module.imports:
					if symbol.import_by_ordinal is True:
						print "%s,import_symbol_ord,DIRECTORY_ENTRY_DELAY_IMPORT,%s-%s" % (self._filename,module.dll,symbol.ordinal)
					else:
						print "%s,import_symbol_ord,DIRECTORY_ENTRY_DELAY_IMPORT,%s-%s-%s" % (self._filename,module.dll,symbol.name,str(symbol.hint))
				
		#::Dynamic Imports::#
		imports_total = len(self._pe.DIRECTORY_ENTRY_IMPORT)
		#::hash em!::#
		import_list=[]
		import_list_raw=[]
		if imports_total > 0:
			for entry in self._pe.DIRECTORY_ENTRY_IMPORT:
				for imp in entry.imports:
					if (imp.name != None) and (imp.name != ""):
						print "%s,import_symbol,DIRECTORY_ENTRY_IMPORT,%s" % (self._filename,entry.dll + "." + imp.name)
						import_list.append(str(entry.dll + "." + imp.name).upper())
						import_list_raw.append(entry.dll + "." + imp.name)
		import_list.sort()
		resultingImports=""
		resultingImportsRaw=""
		for impo in import_list:
			resultingImports+=impo + "\n"

		for impo in import_list_raw:
			resultingImportsRaw+=impo + "\n"

		print "%s,import_names_md5,DIRECTORY_ENTRY_IMPORT,%s" % (self._filename,hashlib.md5(resultingImports).hexdigest())
		print "%s,import_names_ssdeep,DIRECTORY_ENTRY_IMPORT,%s" % (self._filename,ssdeep.hash(resultingImports))
	
		print "%s,import_names_raw_md5,DIRECTORY_ENTRY_IMPORT,%s" % (self._filename,hashlib.md5(resultingImportsRaw).hexdigest())
		print "%s,import_names_raw_ssdeep,DIRECTORY_ENTRY_IMPORT,%s" % (self._filename,ssdeep.hash(resultingImportsRaw))
		
	def list_exports(self):
		if not hasattr(self._pe, 'DIRECTORY_ENTRY_EXPORT'):
			return
		exports_total = len(self._pe.DIRECTORY_ENTRY_EXPORT.symbols)
		if exports_total > 0:
			for entry in self._pe.DIRECTORY_ENTRY_EXPORT.symbols:
				if (entry.name != None) and (entry.name != ""):
					print "%s,export_symbol,DIRECTORY_ENTRY_EXPORT,%s" % (self._filename,entry.name)
		
	def get_virtual_section_info(self):
		for section in self._pe.sections:
			name=str(section.Name.rstrip('\0'))
			data=self._pe.get_data(section.VirtualAddress,section.SizeOfRawData)
			data_md5 = section.get_hash_md5()
			data_ssdeep = ssdeep.hash(data)
			if self._dump_mode == True:
				section_write=open("ripPE-" + name + ".section","wb+")
				section_write.write(data)
				section_write.close()
			print "%s,section_md5,%s,%s" % (self._filename,name,data_md5)
			print "%s,section_ssdeep,%s,%s" % (self._filename,name,data_ssdeep)

	def get_debug(self):
		if not hasattr(self._pe, 'DIRECTORY_ENTRY_DEBUG'):
			return
		for idx in xrange(len(self._pe.OPTIONAL_HEADER.DATA_DIRECTORY)):
			if self._pe.OPTIONAL_HEADER.DATA_DIRECTORY[idx].name == "IMAGE_DIRECTORY_ENTRY_DEBUG":
				name=self._pe.OPTIONAL_HEADER.DATA_DIRECTORY[idx].name
				for dbg in self._pe.DIRECTORY_ENTRY_DEBUG:
					data=self._pe.get_data(dbg.struct.AddressOfRawData,dbg.struct.SizeOfData)
					data_md5=hashlib.md5(data).hexdigest()
					data_ssdeep=ssdeep.hash(data)
					if self._dump_mode == True:
						section_object=open("ripPE-" + name + ".dir","wb+")
						section_object.write(data)
						section_object.close()
					print "%s,debug_hash,DIRECTORY_ENTRY_DEBUG,%s" % (self._filename,data_md5)
					print "%s,debug_ssdeep,DIRECTORY_ENTRY_DEBUG,%s" % (self._filename,data_ssdeep)

	def get_resource_info(self):
		if hasattr(self._pe, 'DIRECTORY_ENTRY_RESOURCE'):
			for resource_type in self._pe.DIRECTORY_ENTRY_RESOURCE.entries:
				if resource_type.name is not None:
					name = "%s" % resource_type.name
				else:
					name = "%s" % pefile.RESOURCE_TYPE.get(resource_type.struct.Id)
				if name == None:
					name = "%d" % resource_type.struct.Id
				if hasattr(resource_type, 'directory'):
					for resource_id in resource_type.directory.entries:
						if hasattr(resource_id, 'directory'):
							for resource_lang in resource_id.directory.entries:
								data = self._pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)
								lang = pefile.LANG.get(resource_lang.data.lang, '*unknown*')
								sublang = pefile.get_sublang_name_for_lang( resource_lang.data.lang, resource_lang.data.sublang )
								resource_md5 = hashlib.md5(data).hexdigest()
								resource_ssdeep = ssdeep.hash(data)
								if self._dump_mode == True:
									resource_dump=open("ripPE-" + name + "-" + resource_md5 + ".rsrc","wb+")
									resource_dump.write(data)
									resource_dump.close()
								print "%s,resource_md5,RESOURCE-%s,%s" % (self._filename,name,resource_md5)
								print "%s,resource_ssdeep,RESOURCE-%s,%s" % (self._filename,name,resource_ssdeep)
	
	def dump_cert(self):
		for idx in xrange(len(self._pe.OPTIONAL_HEADER.DATA_DIRECTORY)):
			if self._pe.OPTIONAL_HEADER.DATA_DIRECTORY[idx].name == 'IMAGE_DIRECTORY_ENTRY_SECURITY':
				address=self._pe.OPTIONAL_HEADER.DATA_DIRECTORY[idx].VirtualAddress
				signature=self._pe.write()[address+8:] #::Thanks Didier Stevens!!
				cert_md5=hashlib.md5(signature).hexdigest()
				cert_ssdeep=ssdeep.hash(signature)
				if self._dump_mode == True:
					hash_dump=open("ripPE-CERT-" + cert_md5 + ".crt","wb+")
					hash_dump.write(signature)
					hash_dump.close()
				print "%s,certificate_md5,DIRECTORY_ENTRY_SECURITY,%s" % (self._filename,cert_md5)
				print "%s,certificate_ssdeep,DIRECTORY_ENTRY_SECURITY,%s" % (self._filename,cert_ssdeep)

def main():

	p = ArgumentParser(description='ripPE.py - script used to rip raw structures from a PE file and list relevant characteristics.',usage='ripPE.py --file=[file] --dump')
	p.add_argument('--file',action='store',dest='ripFile',help='File to Parse',required=True)
	p.add_argument('--section',action='store',dest='ripSection',choices=['all','header','iat','imports','exports','debug','sections','resources','dump_cert'],default='all',help='Section to rip!',required=False)
	p.add_argument('--dump',action='store_true',default=False,dest='dump_mode',help='Dump raw data to file - when not provided only metadata printed to stdout',required=False)							
	args = p.parse_args(sys.argv[1:])	
	
	pe=ripPE(args.ripFile,args.dump_mode)

	if args.ripSection.upper() == "ALL":
		pe.run_all()
	elif args.ripSection.upper() == "HEADER":
		pe.list_standard()
	elif args.ripSection.upper() == "IAT":
		pe.dump_iat()
	elif args.ripSection.upper() == "IMPORTS":
		pe.list_imports()
		pe.dump_import()
	elif args.ripSection.upper() == "EXPORTS":
		pe.list_exports()
	elif args.ripSection.upper() == "DEBUG":
		pe.get_debug()
	elif args.ripSection.upper() == "SECTIONS":
		pe.get_virtual_section_info()
	elif args.ripSection.upper() == "RESOURCES":
		pe.get_resource_info()
	elif args.ripSection.upper() == "DUMP_CERT":
		pe.dump_cert()
	else:
		print "Something bad happened..."

if __name__ == '__main__':
	main()
