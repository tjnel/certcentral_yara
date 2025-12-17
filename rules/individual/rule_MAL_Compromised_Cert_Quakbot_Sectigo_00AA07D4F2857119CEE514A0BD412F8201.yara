import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_00AA07D4F2857119CEE514A0BD412F8201 {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2021-03-15"
      version             = "1.0"

      hash                = "cb4241399f69ba6a8b4e2297b225953b764fb41b4c27dcb3c923c0c54a51d627"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "HANGA GIP d.o.o."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:aa:07:d4:f2:85:71:19:ce:e5:14:a0:bd:41:2f:82:01"
      cert_thumbprint     = "D303630353BB98D67EFCDF298119B9A1BE208D20"
      cert_valid_from     = "2021-03-15"
      cert_valid_to       = "2022-03-15"

      country             = "SI"
      state               = "???"
      locality            = "Velenje"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:aa:07:d4:f2:85:71:19:ce:e5:14:a0:bd:41:2f:82:01"
      )
}
