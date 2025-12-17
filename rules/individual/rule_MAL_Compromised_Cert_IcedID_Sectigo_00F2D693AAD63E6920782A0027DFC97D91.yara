import "pe"

rule MAL_Compromised_Cert_IcedID_Sectigo_00F2D693AAD63E6920782A0027DFC97D91 {
   meta:
      description         = "Detects IcedID with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2020-08-12"
      version             = "1.0"

      hash                = "65ce2081be589354f2b1354ce17e624b18dab29d377190fdc1e88bb5ab8e59a3"
      malware             = "IcedID"
      malware_type        = "Initial access tool"
      malware_notes       = "A malware initially created as a banking trojan but then transitioned to initial access tool used by ransomware gangs: https://www.proofpoint.com/us/blog/threat-insight/fork-ice-new-era-icedid and https://www.proofpoint.com/us/blog/threat-insight/first-step-initial-access-leads-ransomware"

      signer              = "EKO-KHIM TOV"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:f2:d6:93:aa:d6:3e:69:20:78:2a:00:27:df:c9:7d:91"
      cert_thumbprint     = "EC70B38E0EE831F4D532162A9578AE67D462EE3A"
      cert_valid_from     = "2020-08-12"
      cert_valid_to       = "2021-08-12"

      country             = "UA"
      state               = "???"
      locality            = "Kyiv"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:f2:d6:93:aa:d6:3e:69:20:78:2a:00:27:df:c9:7d:91"
      )
}
