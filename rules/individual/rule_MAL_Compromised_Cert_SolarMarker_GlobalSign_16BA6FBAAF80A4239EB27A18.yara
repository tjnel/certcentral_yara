import "pe"

rule MAL_Compromised_Cert_SolarMarker_GlobalSign_16BA6FBAAF80A4239EB27A18 {
   meta:
      description         = "Detects SolarMarker with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2023-10-04"
      version             = "1.0"

      hash                = "5abc14737cb65a1e645bd5a2e3301b0e3e1e861a184034a6cc67ce57ee38f448"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "SCHPITZE ApS"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "16:ba:6f:ba:af:80:a4:23:9e:b2:7a:18"
      cert_thumbprint     = "99CB34D467DC6EE27E34F23BF9B8404156264F95"
      cert_valid_from     = "2023-10-04"
      cert_valid_to       = "2024-10-04"

      country             = "DK"
      state               = "Gentofte"
      locality            = "Hellerup"
      email               = "thomas.bojsen.schmidt@schpitze.com"
      rdn_serial_number   = "34690804"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "16:ba:6f:ba:af:80:a4:23:9e:b2:7a:18"
      )
}
