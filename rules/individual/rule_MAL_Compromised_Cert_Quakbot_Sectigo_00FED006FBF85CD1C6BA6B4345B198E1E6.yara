import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_00FED006FBF85CD1C6BA6B4345B198E1E6 {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2021-02-26"
      version             = "1.0"

      hash                = "ca14dd19ab553fa613a98a71f1d50ef73b9f91436f47b1a35c9ea8a4be2c2cc5"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "LoL d.o.o."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:fe:d0:06:fb:f8:5c:d1:c6:ba:6b:43:45:b1:98:e1:e6"
      cert_thumbprint     = "4BC67ACA336287FF574978EF3BF67C688F6449F2"
      cert_valid_from     = "2021-02-26"
      cert_valid_to       = "2022-02-26"

      country             = "SI"
      state               = "???"
      locality            = "Ljubljana"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:fe:d0:06:fb:f8:5c:d1:c6:ba:6b:43:45:b1:98:e1:e6"
      )
}
