import "pe"

rule MAL_Compromised_Cert_Quakbot_SSL_com_4A3F0BF26862263DAC496033F50594CB {
   meta:
      description         = "Detects Quakbot with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2023-12-15"
      version             = "1.0"

      hash                = "fda2abd24764809fb36d4d2ee7ab5f6e8c06381fe6d9bb191bde62411c96ba92"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "SOFTWARE MEDICAL DEVICES LIMITED"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "4a:3f:0b:f2:68:62:26:3d:ac:49:60:33:f5:05:94:cb"
      cert_thumbprint     = "7917A946ED473A0E81BD4501B0B1736FB1AC653D"
      cert_valid_from     = "2023-12-15"
      cert_valid_to       = "2024-12-14"

      country             = "GB"
      state               = "???"
      locality            = "Tadworth"
      email               = "???"
      rdn_serial_number   = "12713418"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "4a:3f:0b:f2:68:62:26:3d:ac:49:60:33:f5:05:94:cb"
      )
}
