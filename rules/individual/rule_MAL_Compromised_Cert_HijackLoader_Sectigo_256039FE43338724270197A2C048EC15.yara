import "pe"

rule MAL_Compromised_Cert_HijackLoader_Sectigo_256039FE43338724270197A2C048EC15 {
   meta:
      description         = "Detects HijackLoader with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-23"
      version             = "1.0"

      hash                = "8ca17f8770bf57d63512f5689c3cfaa0ea286cb553365595cf4ede21411324bf"
      malware             = "HijackLoader"
      malware_type        = "Unknown"
      malware_notes       = "Ref: https://app.any.run/tasks/8feb84c9-7284-4b88-9ecf-8383f35fc02f"

      signer              = "Wenshui County Hengjiu Zhongtai Information Consulting Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "25:60:39:fe:43:33:87:24:27:01:97:a2:c0:48:ec:15"
      cert_thumbprint     = "9606A1DDF3DFFF3D43F35F0474AC03AC85F73753"
      cert_valid_from     = "2026-01-23"
      cert_valid_to       = "2027-01-23"

      country             = "CN"
      state               = "Shanxi Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91141121MA0KMRHP1G"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "25:60:39:fe:43:33:87:24:27:01:97:a2:c0:48:ec:15"
      )
}
