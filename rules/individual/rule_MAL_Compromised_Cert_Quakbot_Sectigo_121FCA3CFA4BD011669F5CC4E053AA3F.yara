import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_121FCA3CFA4BD011669F5CC4E053AA3F {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2020-12-03"
      version             = "1.0"

      hash                = "692aa8adc305de52bc4c784fc272aaf943b4f8128162b712b24444342078c751"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "Kymijoen Projektipalvelut Oy"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "12:1f:ca:3c:fa:4b:d0:11:66:9f:5c:c4:e0:53:aa:3f"
      cert_thumbprint     = "84B5EF4F981020DF2385754AB1296821FA2F8977"
      cert_valid_from     = "2020-12-03"
      cert_valid_to       = "2021-12-03"

      country             = "FI"
      state               = "???"
      locality            = "KOUVOLA"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "12:1f:ca:3c:fa:4b:d0:11:66:9f:5c:c4:e0:53:aa:3f"
      )
}
