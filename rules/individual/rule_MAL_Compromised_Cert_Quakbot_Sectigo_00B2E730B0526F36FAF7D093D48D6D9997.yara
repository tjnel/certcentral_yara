import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_00B2E730B0526F36FAF7D093D48D6D9997 {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2020-08-13"
      version             = "1.0"

      hash                = "fa8bb8aade3749fb3338d7cd35c9e07781a5422aed193f85e5a3bc1b2fd02c1f"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "Bamboo Connect s.r.o."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:b2:e7:30:b0:52:6f:36:fa:f7:d0:93:d4:8d:6d:99:97"
      cert_thumbprint     = "5036853F8EF939ADEDE39BD7E620C5A9788C24D6"
      cert_valid_from     = "2020-08-13"
      cert_valid_to       = "2021-08-13"

      country             = "CZ"
      state               = "???"
      locality            = "Ostrava"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:b2:e7:30:b0:52:6f:36:fa:f7:d0:93:d4:8d:6d:99:97"
      )
}
