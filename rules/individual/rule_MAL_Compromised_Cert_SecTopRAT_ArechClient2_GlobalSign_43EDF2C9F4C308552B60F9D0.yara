import "pe"

rule MAL_Compromised_Cert_SecTopRAT_ArechClient2_GlobalSign_43EDF2C9F4C308552B60F9D0 {
   meta:
      description         = "Detects SecTopRAT,ArechClient2 with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-12-12"
      version             = "1.0"

      hash                = "a4ef61a4c32010e87894ad322b87d9f24b9b64c20da5b8b53a1545bbcd16e810"
      malware             = "SecTopRAT,ArechClient2"
      malware_type        = "Remote access tool"
      malware_notes       = ""

      signer              = "Connect Computing Inc."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "43:ed:f2:c9:f4:c3:08:55:2b:60:f9:d0"
      cert_thumbprint     = "05A5E0424BA80160D6F77760C974A602A56DBCE4"
      cert_valid_from     = "2024-12-12"
      cert_valid_to       = "2025-12-13"

      country             = "CA"
      state               = "Ontario"
      locality            = "Mississauga"
      email               = "???"
      rdn_serial_number   = "1086757-8"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "43:ed:f2:c9:f4:c3:08:55:2b:60:f9:d0"
      )
}
