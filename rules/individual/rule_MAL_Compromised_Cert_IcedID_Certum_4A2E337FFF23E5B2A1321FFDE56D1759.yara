import "pe"

rule MAL_Compromised_Cert_IcedID_Certum_4A2E337FFF23E5B2A1321FFDE56D1759 {
   meta:
      description         = "Detects IcedID with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2022-08-12"
      version             = "1.0"

      hash                = "3fb07a2e084bdb1180626b3ba7e667951a3bf7a1bea3514b81057e6294cc25e2"
      malware             = "IcedID"
      malware_type        = "Initial access tool"
      malware_notes       = "A malware initially created as a banking trojan but then transitioned to initial access tool used by ransomware gangs: https://www.proofpoint.com/us/blog/threat-insight/fork-ice-new-era-icedid and https://www.proofpoint.com/us/blog/threat-insight/first-step-initial-access-leads-ransomware"

      signer              = "Karolina Klimowska"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "4a:2e:33:7f:ff:23:e5:b2:a1:32:1f:fd:e5:6d:17:59"
      cert_thumbprint     = "B6DB1A48BF8780E1205060BDE207B3FFFA663C04"
      cert_valid_from     = "2022-08-12"
      cert_valid_to       = "2023-08-12"

      country             = "PL"
      state               = "pomorskie"
      locality            = "Gdańsk"
      email               = "???"
      rdn_serial_number   = "389419950"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "4a:2e:33:7f:ff:23:e5:b2:a1:32:1f:fd:e5:6d:17:59"
      )
}
