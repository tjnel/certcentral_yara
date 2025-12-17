import "pe"

rule MAL_Compromised_Cert_NetSupport_RAT_DigiCert_025020668F51235E9ECFFF8CF00DA63E {
   meta:
      description         = "Detects NetSupport RAT with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2021-03-04"
      version             = "1.0"

      hash                = "01910bddacbf2ea878b487dd3dfc2cfbeabf1a3dba94309b4a84c9e6b4b4afc9"
      malware             = "NetSupport RAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This is a weaponised Remote Management and monitoring tool."

      signer              = "Knassar DK ApS"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert EV Code Signing CA"
      cert_serial         = "02:50:20:66:8f:51:23:5e:9e:cf:ff:8c:f0:0d:a6:3e"
      cert_thumbprint     = "59F82837FA672A81841D8FA4D3BA290395C10200"
      cert_valid_from     = "2021-03-04"
      cert_valid_to       = "2022-03-10"

      country             = "DK"
      state               = "???"
      locality            = "Copenhagen"
      email               = "???"
      rdn_serial_number   = "41948590"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert EV Code Signing CA" and
         sig.serial == "02:50:20:66:8f:51:23:5e:9e:cf:ff:8c:f0:0d:a6:3e"
      )
}
