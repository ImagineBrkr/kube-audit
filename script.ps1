Push-Location $args[0]

$Now=Get-Date -Format "yyyy-MM-ddTHH_mm_ss"
$Now="2023-05-03T12_57_48"
terrascan scan -o json | Out-File -FilePath d:/proyectos/shell-script/kube-audit/${Now}_output_terrascan.json -Encoding UTF8

kube-linter lint . --format=json | Out-File -FilePath d:/proyectos/shell-script/kube-audit/${Now}_output_kube_linter.json -Encoding UTF8

trivy fs . -f json | Out-File -FilePath d:/proyectos/shell-script/kube-audit/${Now}_output_trivy.json -Encoding UTF8

kubeaudit all --context gke_mystic-berm-384501_us-central1-a_my-first-cluster --format "json" | Out-File -FilePath d:/proyectos/shell-script/kube-audit/${Now}_output_kube_audit.json -Encoding UTF8

Pop-Location
