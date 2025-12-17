import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_6E0CCBDFB4777E10EA6221B90DC350C2 {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2020-10-16"
      version             = "1.0"

      hash                = "664772bd38ffaf9acb17b9485747ba706d7ddf1d8374f8fd6594251d1df85be9"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "TRAUMALAB INTERNATIONAL APS"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "6e:0c:cb:df:b4:77:7e:10:ea:62:21:b9:0d:c3:50:c2"
      cert_thumbprint     = "A6E18ECDB7F82D3E1D609536AFBE0225ED04D123"
      cert_valid_from     = "2020-10-16"
      cert_valid_to       = "2021-10-16"

      country             = "DK"
      state               = "???"
      locality            = "Bagsværd"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "6e:0c:cb:df:b4:77:7e:10:ea:62:21:b9:0d:c3:50:c2"
      )
}
