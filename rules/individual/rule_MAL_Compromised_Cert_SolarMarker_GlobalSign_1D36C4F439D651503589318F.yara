import "pe"

rule MAL_Compromised_Cert_SolarMarker_GlobalSign_1D36C4F439D651503589318F {
   meta:
      description         = "Detects SolarMarker with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2022-05-02"
      version             = "1.0"

      hash                = "cce973b40f864284f2226213f1989c45861d89fd62eb0e311e880f5d017e23b2"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "REDWOOD MARKETING SOLUTIONS INC."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "1d:36:c4:f4:39:d6:51:50:35:89:31:8f"
      cert_thumbprint     = "78AC9124F9664BEC9D35D80B4F081B42CC0ED487"
      cert_valid_from     = "2022-05-02"
      cert_valid_to       = "2023-05-03"

      country             = "CA"
      state               = "Ontario"
      locality            = "Grimsby"
      email               = "Williams.A@redwood-canada.com"
      rdn_serial_number   = "1005446-1"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "1d:36:c4:f4:39:d6:51:50:35:89:31:8f"
      )
}
