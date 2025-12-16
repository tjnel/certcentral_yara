import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_009BD81A9ADAF71F1FF081C1F4A05D7FD7 {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2020-10-03"
      version             = "1.0"

      hash                = "d86093212dafd8a363412060ce27984f98829de5cbe684978407f6478b8d68cf"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "SMART TOYS AND GAMES, INC"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:9b:d8:1a:9a:da:f7:1f:1f:f0:81:c1:f4:a0:5d:7f:d7"
      cert_thumbprint     = "122DEB269E3DF6CEE8396E450D66CB679CEF38FC"
      cert_valid_from     = "2020-10-03"
      cert_valid_to       = "2021-10-03"

      country             = "US"
      state               = "California"
      locality            = "SAN FRANCISCO"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:9b:d8:1a:9a:da:f7:1f:1f:f0:81:c1:f4:a0:5d:7f:d7"
      )
}
