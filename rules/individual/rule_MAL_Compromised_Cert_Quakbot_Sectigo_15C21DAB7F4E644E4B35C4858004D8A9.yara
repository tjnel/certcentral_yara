import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_15C21DAB7F4E644E4B35C4858004D8A9 {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2022-04-06"
      version             = "1.0"

      hash                = "82dae5e93006e8bbbef21b855953a5445999ec08a89852f40bdc848c9c072186"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "P.REGO, s.r.o."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "15:c2:1d:ab:7f:4e:64:4e:4b:35:c4:85:80:04:d8:a9"
      cert_thumbprint     = "328264490A82A576FC5EE14D0B1A879BDEA1EBAE"
      cert_valid_from     = "2022-04-06"
      cert_valid_to       = "2023-04-06"

      country             = "SK"
      state               = "Žilinský kraj"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "15:c2:1d:ab:7f:4e:64:4e:4b:35:c4:85:80:04:d8:a9"
      )
}
