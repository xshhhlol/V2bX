package cmd

import (
	"fmt"
	"github.com/InazumaV/V2bX/common/externalweb"

	"github.com/spf13/cobra"
)

var (
	version  = "TempVersion" //use ldflags replace
	codename = "V2bX"
	intro    = "A V2board backend based on multi core"
)

var versionCommand = cobra.Command{
	Use:   "version",
	Short: "Print version info",
	Run: func(_ *cobra.Command, _ []string) {
		showVersion()
	},
}

func init() {
	command.AddCommand(&versionCommand)
	command.AddCommand(&cobra.Command{Use: "features", Short: "Print optional deployment capabilities", Run: func(cmd *cobra.Command, args []string) {
		if externalweb.SupportsTLSProxy() {
			fmt.Println("external-web-v1")
			fmt.Println("external-web-ubuntu-lts-v1")
		}
		if externalweb.SupportsAllTLSProxies() {
			fmt.Println("external-web-v2")
		}
	}})
}

func showVersion() {
	fmt.Println(` 
  _/      _/    _/_/    _/        _/      _/   
 _/      _/  _/    _/  _/_/_/      _/  _/      
_/      _/      _/    _/    _/      _/         
 _/  _/      _/      _/    _/    _/  _/        
  _/      _/_/_/_/  _/_/_/    _/      _/        
                                                `)
	fmt.Printf("%s %s (%s) \n", codename, version, intro)
	//fmt.Printf("Supported cores: %s\n", strings.Join(vCore.RegisteredCore(), ", "))
	// Warning
	//fmt.Println(Warn("This version need V2board version >= 1.7.0."))
	//fmt.Println(Warn("The version have many changed for config, please check your config file"))
}
