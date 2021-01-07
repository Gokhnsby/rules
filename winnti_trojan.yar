rule Winnti_trojan 
{
 
   meta:
	
       	alert_severity = "HIGH"
       	log = "false"
       	author = "gokhansobay"
       	weight = 10
       	alert = true
       	version = 1
       	date = "2019-06-11"
       	description = "Threat APT actor from China"
      	hash0 = "94e127d627b3af9015396810a35af1c" .dat_loader
       	hash1 = "ce9baade675cae3d179cb703c87422fe" hack_tool
       	hash2 = "aaf8f7895c5ffbb855254d322f114527" .dat_loader
   	hash3 = "52449d12ae6e5af5ae22150c740e262c" hack_tool
	hash4 = "9864437fc844d928a67e8c6ecff2edd6" hack_tool
	hash5 = "dd34560ea3e6272663c4c78ad1e2c8b4" dll_loader
       	hash6 = "22a59a227bddcb158403a023fe2630ef" dat_loader
	hash7 = "7c76f5f65f17329bf1468e6b06631bd7" dll_loader
	hash8 = "79939742f6efd865c112f764ebdaf7c5" dat_loader
	hash9 = "048b0012d4a389b5489e0e4ee4a5b615" dat_loader
	hash10 = "df67017e9c102b23b9da2db008aff7a1" dat_file
	hash11 = "195dd09a56e288d13c0c46ff117a5332" dat_loader


   strings:
	$s0 = "\system32\dpapi.dll"
	$s1 = ".dat"
  	$s2 = "system32\\dpapi.dll"
  	$s3 = "windows\system32\*.dat"

    condition:
        all of them
}
