import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_00AA1D84779792B57F91FE7A4BDE041942 {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2021-12-19"
      version             = "1.0"

      hash                = "8ad652ed5304408015e65d5ab8ecf65fecf8f00c1e5eb97606bd01d6031f5418"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "AXIUM NORTHWESTERN HYDRO INC."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "00:aa:1d:84:77:97:92:b5:7f:91:fe:7a:4b:de:04:19:42"
      cert_thumbprint     = "6C15651791EA8D91909A557EADABE3581B4D1BE9"
      cert_valid_from     = "2021-12-19"
      cert_valid_to       = "2022-12-19"

      country             = "CA"
      state               = "Ontario"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "00:aa:1d:84:77:97:92:b5:7f:91:fe:7a:4b:de:04:19:42"
      )
}
