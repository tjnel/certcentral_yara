import "pe"

rule MAL_Compromised_Cert_SolarMarker_Certum_092A8190ED1DEA673F505593BED137D4 {
   meta:
      description         = "Detects SolarMarker with compromised cert (Certum)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2020-11-26"
      version             = "1.0"

      hash                = "bbfae2ab644c8d0f1ba82b01032b1962c43855cc6716193ce872ac16cda166df"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "SMARTYUNITI OOO"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing CA SHA2"
      cert_serial         = "09:2a:81:90:ed:1d:ea:67:3f:50:55:93:be:d1:37:d4"
      cert_thumbprint     = "2C44BA1A57FD7C40785D3CFEA9919C0D50BB50D9"
      cert_valid_from     = "2020-11-26"
      cert_valid_to       = "2021-11-26"

      country             = "RU"
      state               = "St. Petersburg"
      locality            = "St. Petersburg"
      email               = "???"
      rdn_serial_number   = "1147847039383"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing CA SHA2" and
         sig.serial == "09:2a:81:90:ed:1d:ea:67:3f:50:55:93:be:d1:37:d4"
      )
}
