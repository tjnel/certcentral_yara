import "pe"

rule MAL_Compromised_Cert_CobaltStrike_Sectigo_2A52ACB34BD075AC9F58771D2A4BBFBA {
   meta:
      description         = "Detects CobaltStrike with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2020-02-28"
      version             = "1.0"

      hash                = "a32e37ae08d6a723dff7313d96bc7e23fe9b7db18295e2916f3c935530329919"
      malware             = "CobaltStrike"
      malware_type        = "Remote access tool"
      malware_notes       = "A commercial red-teaming product which is weaponized by a wide range of cybercriminals: https://malpedia.caad.fkie.fraunhofer.de/details/win.cobalt_strike"

      signer              = "Katarzyna Galganek mim e coc"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "2a:52:ac:b3:4b:d0:75:ac:9f:58:77:1d:2a:4b:bf:ba"
      cert_thumbprint     = "78063497F9FD11DB5D3DF56F137E0BA7D90F5900"
      cert_valid_from     = "2020-02-28"
      cert_valid_to       = "2021-02-27"

      country             = "PL"
      state               = "???"
      locality            = "Krakow"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "2a:52:ac:b3:4b:d0:75:ac:9f:58:77:1d:2a:4b:bf:ba"
      )
}
