import "pe"

rule MAL_Compromised_Cert_Coinminer_Sectigo_009E9428089C105FE19B7EE10BC764EBF4 {
   meta:
      description         = "Detects Coinminer with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-01-26"
      version             = "1.0"

      hash                = "883d86b3c3ad92c957f65175acc15247b2c57be2ec50fb672cb848ec55febc37"
      malware             = "Coinminer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "IntelliBreeze Software AB"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:9e:94:28:08:9c:10:5f:e1:9b:7e:e1:0b:c7:64:eb:f4"
      cert_thumbprint     = "BF126F9346924B3376AB4436D56E9BF30D13355C"
      cert_valid_from     = "2024-01-26"
      cert_valid_to       = "2027-01-26"

      country             = "SE"
      state               = "Stockholms län"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "559047-8920"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:9e:94:28:08:9c:10:5f:e1:9b:7e:e1:0b:c7:64:eb:f4"
      )
}
