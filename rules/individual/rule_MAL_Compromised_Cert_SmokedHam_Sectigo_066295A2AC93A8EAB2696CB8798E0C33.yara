import "pe"

rule MAL_Compromised_Cert_SmokedHam_Sectigo_066295A2AC93A8EAB2696CB8798E0C33 {
   meta:
      description         = "Detects SmokedHam with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-15"
      version             = "1.0"

      hash                = "abad3e70da1afa3c8a34ee02e658004e254bc140caf873d6a62d8deeeb9d934d"
      malware             = "SmokedHam"
      malware_type        = "Backdoor"
      malware_notes       = "The malware masquerades as an administrative tool. When executed, it downloads and decrypts additional payloads: https://medium.com/trac-labs/who-ordered-the-smokedham-backdoor-delicacies-in-the-wild-87f51e2e5bd2"

      signer              = "Chengdu Jiameini Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "06:62:95:a2:ac:93:a8:ea:b2:69:6c:b8:79:8e:0c:33"
      cert_thumbprint     = "80AD2ED74647C2E129DCD310B76A613BC4C36E84"
      cert_valid_from     = "2025-10-15"
      cert_valid_to       = "2026-10-15"

      country             = "CN"
      state               = "Sichuan Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "06:62:95:a2:ac:93:a8:ea:b2:69:6c:b8:79:8e:0c:33"
      )
}
