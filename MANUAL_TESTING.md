# BeeWAF — Guide de Test Manuel

## Prérequis
```bash
cd /home/kali/seethroughwalls
# Démarrer le conteneur
docker start beewaf_sklearn
# OU lancer localement
. .venv/bin/activate
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

## 1. Test Endpoints de Base

### Health Check
```bash
curl http://127.0.0.1:8000/health
# Attendu: {"status":"ok","anomaly_detector_trained":true,"rules_count":9}
```

### Page d'accueil
```bash
curl http://127.0.0.1:8000/
# Attendu: {"service":"BeeWAF","status":"running"}
```

### Admin Rules
```bash
curl http://127.0.0.1:8000/admin/rules
# Attendu: {"rules": [[pattern, type], ...]}
```

## 2. Test Protection Injection SQL

### Requête benign (doit passer)
```bash
curl -X POST http://127.0.0.1:8000/echo \
  -H "Content-Type: text/plain" \
  -d "username=admin&password=secret123"
# Attendu: HTTP 200, body: "username=admin&password=secret123"
```

### SQLi classique (doit bloquer)
```bash
curl -X POST http://127.0.0.1:8000/echo \
  -H "Content-Type: text/plain" \
  -d "' OR 1=1 --"
# Attendu: HTTP 403, {"blocked":true,"reason":"regex-sqli"}
```

### SQLi UNION (doit bloquer)
```bash
curl -X POST http://127.0.0.1:8000/echo \
  -H "Content-Type: text/plain" \
  -d "' UNION SELECT * FROM users --"
# Attendu: HTTP 403, {"blocked":true,"reason":"regex-sqli"}
```

### SQLi DROP TABLE (doit bloquer)
```bash
curl -X POST http://127.0.0.1:8000/echo \
  -H "Content-Type: text/plain" \
  -d "; DROP TABLE users;"
# Attendu: HTTP 403, {"blocked":true,"reason":"regex-sqli"}
```

## 3. Test Protection XSS

### XSS script tag (doit bloquer)
```bash
curl -X POST http://127.0.0.1:8000/echo \
  -H "Content-Type: text/plain" \
  -d '<script>alert(1)</script>'
# Attendu: HTTP 403, {"blocked":true,"reason":"regex-xss"}
```

### XSS onerror (doit bloquer)
```bash
curl -X POST http://127.0.0.1:8000/echo \
  -H "Content-Type: text/plain" \
  -d '<img src=x onerror=alert(1)>'
# Attendu: HTTP 403, {"blocked":true,"reason":"regex-xss"}
```

### XSS javascript: (doit bloquer)
```bash
curl -X POST http://127.0.0.1:8000/echo \
  -H "Content-Type: text/plain" \
  -d '<a href="javascript:alert(1)">click</a>'
# Attendu: HTTP 403, {"blocked":true,"reason":"regex-xss"}
```

## 4. Test Rate Limiting

### Requêtes rapides (> 10 en 60s)
```bash
# Lancer 15 requêtes rapides avec la même IP
for i in {1..15}; do
  curl -s -w "\nHTTP_CODE:%{http_code}" \
    -H "X-Real-IP: 192.0.2.99" \
    -X POST http://127.0.0.1:8000/echo \
    -d "request_$i"
  echo ""
done
# Attendu: ~10 premières → HTTP 200, suivantes → HTTP 429
```

### Vérifier limite atteinte
```bash
curl -s -H "X-Real-IP: 192.0.2.99" \
  -X POST http://127.0.0.1:8000/echo \
  -d "test" -w "\nHTTP_CODE:%{http_code}\n"
# Si limite atteinte: HTTP 429, {"blocked":true,"reason":"rate-limit"}
```

## 5. Test Détecteur d'Anomalies

Le détecteur analyse les features (longueur body, caractères spéciaux, mots-clés SQL/XSS).

### Payload anormal (peut être bloqué par ML)
```bash
curl -X POST http://127.0.0.1:8000/echo \
  -H "Content-Type: text/plain" \
  -d "$(python3 -c 'print("A"*10000 + "select union drop" * 100)')"
# Peut retourner: HTTP 403, {"blocked":true,"reason":"anomaly"}
```

## 6. Test ClamAV (si clamd actif)

### Payload EICAR (test virus standard)
```bash
curl -X POST http://127.0.0.1:8000/echo \
  -H "Content-Type: text/plain" \
  -d 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
# Si ClamAV actif: HTTP 403, {"blocked":true,"reason":"clamav-detected"}
# Si ClamAV absent: HTTP 200 (passthrough)
```

## 7. Test Verbose avec Headers

### Voir tous les headers de réponse
```bash
curl -v -X POST http://127.0.0.1:8000/echo \
  -H "Content-Type: text/plain" \
  -d "test payload"
```

### Voir temps de réponse
```bash
curl -w "\nTime: %{time_total}s\nHTTP: %{http_code}\n" \
  -X POST http://127.0.0.1:8000/echo \
  -d "hello"
```

## 8. Test Logs Container

### Voir logs en temps réel
```bash
docker logs -f beewaf_sklearn
```

### Voir dernières 100 lignes
```bash
docker logs --tail 100 beewaf_sklearn
```

### Filtrer blocages
```bash
docker logs beewaf_sklearn 2>&1 | grep -i blocked
```

## 9. Test Performance

### 100 requêtes benign
```bash
time for i in {1..100}; do
  curl -s http://127.0.0.1:8000/health > /dev/null
done
```

### Benchmark avec Apache Bench
```bash
# Installer ab si absent
sudo apt install apache2-utils -y

# Test 1000 requêtes, 10 concurrent
ab -n 1000 -c 10 http://127.0.0.1:8000/health
```

## 10. Test Kubernetes (si déployé)

### Port-forward vers le pod
```bash
kubectl port-forward deployment/beewaf 8000:8000
```

### Tester via service
```bash
kubectl run -it --rm debug --image=curlimages/curl --restart=Never -- \
  curl http://beewaf-svc/health
```

## 11. Scenarios Avancés

### Test combiné (SQLi + XSS)
```bash
curl -X POST http://127.0.0.1:8000/echo \
  -d "name=<script>alert(1)</script>&id=' OR 1=1 --"
# Attendu: HTTP 403 (premier pattern matché)
```

### Test bypass tentative
```bash
# Encodage URL
curl -X POST http://127.0.0.1:8000/echo \
  -d "%3Cscript%3Ealert(1)%3C/script%3E"
# Décoder et bloquer si détecté
```

### Test case-insensitive
```bash
curl -X POST http://127.0.0.1:8000/echo \
  -d "SeLeCt * FrOm users"
# Attendu: HTTP 403 (regex case-insensitive)
```

## 12. Vérification État

### Status complet
```bash
echo "=== Container Status ==="
docker ps --filter name=beewaf_sklearn

echo -e "\n=== Health Check ==="
curl -s http://127.0.0.1:8000/health | jq .

echo -e "\n=== Rules Count ==="
curl -s http://127.0.0.1:8000/admin/rules | jq '.rules | length'

echo -e "\n=== Model Status ==="
ls -lh models/model.pkl
```

## Résultats Attendus

| Test | HTTP Code | Body/Reason |
|------|-----------|-------------|
| Health check | 200 | `{"status":"ok",...}` |
| Benign request | 200 | Echo du body |
| SQLi | 403 | `{"blocked":true,"reason":"regex-sqli"}` |
| XSS | 403 | `{"blocked":true,"reason":"regex-xss"}` |
| Rate limit exceeded | 429 | `{"blocked":true,"reason":"rate-limit"}` |
| Anomaly detected | 403 | `{"blocked":true,"reason":"anomaly"}` |
| ClamAV detected | 403 | `{"blocked":true,"reason":"clamav-detected"}` |
