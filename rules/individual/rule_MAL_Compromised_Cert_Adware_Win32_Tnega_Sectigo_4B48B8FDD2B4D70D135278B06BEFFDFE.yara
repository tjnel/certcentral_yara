import "pe"

rule MAL_Compromised_Cert_Adware_Win32_Tnega_Sectigo_4B48B8FDD2B4D70D135278B06BEFFDFE {
   meta:
      description         = "Detects Adware:Win32/Tnega with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-09-02"
      version             = "1.0"

      hash                = "7ed76946c8ef0829f1011ce230cae7b63c3bf061de1e5f9d8da616a97ad6e4c5"
      malware             = "Adware:Win32/Tnega"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Crowd Sync LLC"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "4b:48:b8:fd:d2:b4:d7:0d:13:52:78:b0:6b:ef:fd:fe"
      cert_thumbprint     = "0199082ab77502eb39b605f22ec3c7b6e168a71def86fbc5c648fb7992c42f3c"
      cert_valid_from     = "2024-09-02"
      cert_valid_to       = "2025-09-02"

      country             = "US"
      state               = "Missouri"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "4b:48:b8:fd:d2:b4:d7:0d:13:52:78:b0:6b:ef:fd:fe"
      )
}
