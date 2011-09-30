##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary
        include Msf::Exploit::Remote::Tcp
        include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'         => 'VSploit File Stream Generator',
			'Version'      => '$Revision$',
			'Description'  => 'This module generates network file streams for testing IDS/IPS/etc.',
			'Author'       => 'MJC',
			'License'      => MSF_LICENSE
		)

		register_options(
			[
				OptString.new('PROTO',[TRUE, "TCP/UDP","TCP"]),
				Opt::RPORT(80),
				OptString.new('FILE_SIG',[TRUE, "Specifies file signature: EXE, ZIP, RAR, or ELF","RAR"]),
				OptInt.new('KB',[TRUE, "Stream pad size in kilobytes: Default 64KB",64])
			], self.class)

	end
	
	def pad
		padding = [Rex::Text.rand_text_hex(datastore['KB'] * 1024)].pack("H*")
		padding += "\x00" * 128
	end

	# Create data with RAR file header
	def rar
		rar_sig = "526172211A0700"
		rar_sig = [rar_sig].pack("H*")
		rar_sig += pad
	end
	
	# Create data with ZIP(PK) file header
	def zip
		zip_sig  = "504B03040A0000000000BA6B0B3F00"
		zip_sig += "000000000000000000000006001C00"
		zip_sig = [zip_sig].pack("H*")
		zip_sig += pad
	end

	# Create data with Windows EXE file header 
	def exe
		exe_sig  = "4D5A90000300000004000000FFFF0000"
		exe_sig += "B8000000000000004000000000000000"
		exe_sig += "00000000000000000000000000000000"
		exe_sig += "000000000000000000000000D0000000"
		exe_sig += "0E1FBA0E00B409CD21B8014CCD215468"
		exe_sig += "69732070726F6772616D2063616E6E6F"
		exe_sig += "742062652072756E20696E20444F5320"
		exe_sig += "6D6F64652E0D0D0A2400000000000000"
		exe_sig += "3924F7DD7D45998E7D45998E7D45998E"
		exe_sig += "5A83E28E7E45998E7D45988E7B45998E"
		exe_sig += "743D1D8E7C45998E743D088E7C45998E"
		exe_sig += "526963687D45998E0000000000000000"
		exe_sig += "00000000000000000000000000000000"
		exe_sig += "50450000"
		exe_sig = [exe_sig].pack("H*")
		exe_sig += pad
	end

	# Create data with UNIX/Linux Executable ELF header 
	def elf
		elf_sig = "7F454C46"
		elf_sig = [elf_sig].pack("H*")
		elf_sig += pad 
	end

    def run_host(ip)

		case(datastore['FILE_SIG'].upcase)
			when "ELF"
				data = elf
			when "EXE"
				data = exe
			when "RAR"
				data = rar
			when "ZIP"
				data = zip
			#else
			#	print_error("Please set FILE_TYPE to: ELF, EXE, RAR, or ZIP")
			#	return
		end

		# Create TCP connection and send data

		if datastore['PROTO'].upcase == "TCP"
			
			print_status("Sending #{datastore['FILE_SIG'].upcase} file stream to #{datastore['RHOSTS']} via TCP")
		        connect()
			sock.puts(data) # Send data
		        disconnect()

		# Create UDP socket and send data

		elsif datastore['PROTO'].upcase == "UDP"

			print_status("Sending #{datastore['FILE_SIG'].upcase} file stream to #{datastore['RHOSTS']} via UDP")

	                udp_sock = Rex::Socket::Udp.create(
	                        'Context'   =>
	                                {
	                                        'Msf'        => framework,
	                                        'MsfExploit' => self,
	                                })
			udp_sock.sendto(data, ip, datastore['RPORT'])  # Send data

		end

    end


end
