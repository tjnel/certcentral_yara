import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_00A918455C0D4DA7CA474F41F11A7CF38C {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2021-04-21"
      version             = "1.0"

      hash                = "e7a6e97363a3160280cdff69153dad3255759fc76dd10fc990432fd6c8f20cd4"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "MIDDRA INTERNATIONAL CORP."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:a9:18:45:5c:0d:4d:a7:ca:47:4f:41:f1:1a:7c:f3:8c"
      cert_thumbprint     = "CE69E1DC8E1BC1B49A523E7B7B0E9A22FAC826AB"
      cert_valid_from     = "2021-04-21"
      cert_valid_to       = "2022-04-21"

      country             = "US"
      state               = "California"
      locality            = "Los Angeles"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:a9:18:45:5c:0d:4d:a7:ca:47:4f:41:f1:1a:7c:f3:8c"
      )
}
