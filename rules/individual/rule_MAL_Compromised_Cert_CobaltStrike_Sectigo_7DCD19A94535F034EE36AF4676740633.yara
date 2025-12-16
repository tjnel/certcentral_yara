import "pe"

rule MAL_Compromised_Cert_CobaltStrike_Sectigo_7DCD19A94535F034EE36AF4676740633 {
   meta:
      description         = "Detects CobaltStrike with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2020-12-29"
      version             = "1.0"

      hash                = "6220127ada00d84b58d718152748cd2c62007b1de92201701dc2968d2b00e31f"
      malware             = "CobaltStrike"
      malware_type        = "Remote access tool"
      malware_notes       = "A commercial red-teaming product which is weaponized by a wide range of cybercriminals: https://malpedia.caad.fkie.fraunhofer.de/details/win.cobalt_strike"

      signer              = "Toko Saya ApS"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "7d:cd:19:a9:45:35:f0:34:ee:36:af:46:76:74:06:33"
      cert_thumbprint     = "F4CBAA5575E43486D773A87CFDDDB7D2929AD549"
      cert_valid_from     = "2020-12-29"
      cert_valid_to       = "2021-12-29"

      country             = "DK"
      state               = "???"
      locality            = "Odense SV"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "7d:cd:19:a9:45:35:f0:34:ee:36:af:46:76:74:06:33"
      )
}
