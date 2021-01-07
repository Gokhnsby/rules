rule ramnit_trojan 
{
 
   meta:
	
       	alert_severity = "HIGH"
       	log = "false"
       	author = "gokhansobay"
       	weight = 10
       	alert = true
       	version = 1
       	date = "2019-06-10"
       	description = "Ramnit Banking Trojan"
      	hash0 = "bd19c8496017c962b9cd8508346e3878" Ramnit (Main Installer)
       	hash1 = "ff5e1f27193ce51eec318714ef038bef" Ramnit (UPX Packed)
       	hash2 = "44e92c4b5f440b756f8fb0c9eeb460b2" Ramnit (Unpacked)
   	hash3 = "ed362f56ad7cd9d5c4e2415436c1c129" Ramnit (DLL)
	hash4 = "606215cf65fab017cff76463402a15e2" Ramnit (DLL)
        

   strings:
	$s0 = "winsxs\\*\\tiworker.exe"
	$s1 = "system\\currentcontrolset\\control"
  	$s2 = "system32\\taskhostw.exe"
  	$s3 = "servicing\\trustedinstaller.exe"
	$s4 = "hooker.dll"
	$s5 = "cookie.dll"
	$s6 = "vnc.dll"

    condition:
        all of them
}
