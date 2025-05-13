package handlers

import (
	"net/http"
	"strconv"
	"text/template"

	"github.com/Shivam-Patel-G/blackhole-blockchain/services/wallet/wallet-backend/client"
)

func StakeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		r.ParseForm()
		address := r.FormValue("address")
		target := r.FormValue("target")
		amount, _ := strconv.ParseUint(r.FormValue("amount"), 10, 64)
		stakeType := r.FormValue("stakeType")
		err := client.Stake(address, target, amount, stakeType)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write([]byte("Stake submitted"))
	} else {
		t, _ := template.ParseFiles("templates/staking.html")
		t.Execute(w, nil)
	}
}
