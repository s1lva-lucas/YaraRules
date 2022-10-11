rule more_eggs_backdoor{

    meta:
        author = "Lucas Silva"
        Description = "More_Eggs JScript Backdoor"
	
	strings:
		$lnk = { 4C 00 00 00 01 14 02 00 }
		$a1 = "cmd.exe" fullword wide ascii 
		$a2 = "inf" fullword wide ascii 
		$a3 = "OCXs" wide ascii
		$a4 = "ieu" fullword wide ascii
		$a5 = "wmi" fullword wide ascii
		$a6 = "call" fullword wide ascii

	condition:
		$lnk at 0 
		and all of them

}