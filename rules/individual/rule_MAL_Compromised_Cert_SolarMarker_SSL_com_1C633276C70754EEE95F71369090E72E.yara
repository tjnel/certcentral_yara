import "pe"

rule MAL_Compromised_Cert_SolarMarker_SSL_com_1C633276C70754EEE95F71369090E72E {
   meta:
      description         = "Detects SolarMarker with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2023-08-16"
      version             = "1.0"

      hash                = "250fe7be536bb8674dd7e0e7c4de2ca1e3311ed657181d950dda6590a3bded51"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "ТОВ \"Айтипути\""
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "1c:63:32:76:c7:07:54:ee:e9:5f:71:36:90:90:e7:2e"
      cert_thumbprint     = "527F3B9655590D119DA9629CFC408251E185394F"
      cert_valid_from     = "2023-08-16"
      cert_valid_to       = "2024-08-15"

      country             = "UA"
      state               = "Dnipropetrovsk Oblast"
      locality            = "Dnipro"
      email               = "???"
      rdn_serial_number   = "45324891"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "1c:63:32:76:c7:07:54:ee:e9:5f:71:36:90:90:e7:2e"
      )
}
