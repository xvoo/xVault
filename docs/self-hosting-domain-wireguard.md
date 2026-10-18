# Exposer xVault sur un nom de domaine via un VPS-relais (WireGuard, IP masquée)

## Principe

Le VPS ne sert **qu'à encaisser l'IP publique**. Il ne fait tourner ni Caddy ni aucune appli : il reçoit les paquets sur ses ports 80/443 et les **redirige au niveau réseau (NAT/DNAT)** vers ton Debian via le tunnel WireGuard. Ton Debian reçoit le trafic comme s'il arrivait directement chez lui, termine le TLS lui-même (Caddy local), et ton IP maison n'apparaît jamais nulle part — ni dans le DNS, ni dans aucun certificat, ni dans aucun log public.

```
Internet ──▶ DNS (domaine) ──▶ VPS (IP publique)
                                   │  iptables DNAT :80/:443
                                   │  (le VPS ne déchiffre rien, il relaie des octets)
                              Tunnel WireGuard
                                   │
                          Debian (10.10.0.2)
                                   │
                         Caddy (TLS + reverse proxy, en local)
                                   │
                              xVault :58951
```

Remplace partout :
- `VPS_IP_PUBLIQUE` → IP publique du VPS
- `vault.exemple.com` → ton domaine
- `eth0` → l'interface publique réelle du VPS (vérifie avec `ip -4 addr` ou `ip route get 1.1.1.1`, certains hébergeurs utilisent `ens3`, `enp1s0`, etc.)
- `10.10.0.1` (VPS) / `10.10.0.2` (Debian) → IPs du tunnel, arbitraires mais privées

---

## 1. WireGuard — générer les clés

**Sur le VPS :**

```bash
sudo apt update && sudo apt install -y wireguard iptables
umask 077
wg genkey | tee /etc/wireguard/vps-private.key | wg pubkey > /etc/wireguard/vps-public.key
cat /etc/wireguard/vps-public.key
```

**Sur le Debian :**

```bash
sudo apt update && sudo apt install -y wireguard
umask 077
wg genkey | tee /etc/wireguard/laptop-private.key | wg pubkey > /etc/wireguard/laptop-public.key
cat /etc/wireguard/laptop-public.key
```

Tu as maintenant 2 paires de clés. Chaque machine donne sa **clé publique** à l'autre.

---

## 2. Config WireGuard du VPS (avec le forwarding intégré)

C'est ici que se joue tout le "VPS = juste une IP" : les règles `PostUp`/`PostDown` s'appliquent et se retirent automatiquement avec le tunnel.

`/etc/wireguard/wg0.conf` sur le VPS :

```ini
[Interface]
PrivateKey = <contenu de vps-private.key>
Address = 10.10.0.1/24
ListenPort = 51820
SaveConfig = false

PostUp = sysctl -w net.ipv4.ip_forward=1
PostUp = iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j DNAT --to-destination 10.10.0.2:80
PostUp = iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 443 -j DNAT --to-destination 10.10.0.2:443
PostUp = iptables -t nat -A POSTROUTING -o wg0 -j MASQUERADE
PostUp = iptables -A FORWARD -i eth0 -o wg0 -p tcp --dport 80 -j ACCEPT
PostUp = iptables -A FORWARD -i eth0 -o wg0 -p tcp --dport 443 -j ACCEPT
PostUp = iptables -A FORWARD -i wg0 -o eth0 -m state --state ESTABLISHED,RELATED -j ACCEPT

PostDown = iptables -t nat -D PREROUTING -i eth0 -p tcp --dport 80 -j DNAT --to-destination 10.10.0.2:80
PostDown = iptables -t nat -D PREROUTING -i eth0 -p tcp --dport 443 -j DNAT --to-destination 10.10.0.2:443
PostDown = iptables -t nat -D POSTROUTING -o wg0 -j MASQUERADE
PostDown = iptables -D FORWARD -i eth0 -o wg0 -p tcp --dport 80 -j ACCEPT
PostDown = iptables -D FORWARD -i eth0 -o wg0 -p tcp --dport 443 -j ACCEPT
PostDown = iptables -D FORWARD -i wg0 -o eth0 -m state --state ESTABLISHED,RELATED -j ACCEPT

[Peer]
# Debian (xVault)
PublicKey = <clé publique du Debian>
AllowedIPs = 10.10.0.2/32
```

- `DNAT` : tout ce qui arrive sur le port public 80/443 du VPS est renvoyé vers `10.10.0.2` (ton Debian), sans jamais être déchiffré ici.
- `MASQUERADE` : indispensable — sans ça, ton Debian essaierait de répondre directement au vrai client internet (qu'il ne connaît pas via le tunnel) au lieu de répondre au VPS. Avec MASQUERADE, pour ton Debian, tout le trafic semble venir du VPS (`10.10.0.1`), donc la réponse repart par le même chemin.

**Pourquoi mettre les règles dans PostUp/PostDown plutôt qu'`iptables-persistent` ?** Elles s'activent/se désactivent avec l'interface `wg0` elle-même — pas besoin d'un service séparé, et si tu coupes le tunnel, le NAT disparaît aussi (propre).

Démarre :

```bash
sudo systemctl enable --now wg-quick@wg0
sudo wg show
```

Firewall du VPS :

```bash
sudo apt install -y ufw
sudo ufw allow OpenSSH
sudo ufw allow 51820/udp
# Le forwarding passe par la chaîne FORWARD, pas INPUT — si ufw bloque le forward par défaut :
sudo sed -i 's/DEFAULT_FORWARD_POLICY="DROP"/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw
sudo ufw enable
sudo ufw reload
```

---

## 3. Config WireGuard du Debian

`/etc/wireguard/wg0.conf` sur le Debian :

```ini
[Interface]
PrivateKey = <contenu de laptop-private.key>
Address = 10.10.0.2/24

[Peer]
PublicKey = <clé publique du VPS>
Endpoint = VPS_IP_PUBLIQUE:51820
AllowedIPs = 10.10.0.1/32
PersistentKeepalive = 25
```

`PersistentKeepalive` est obligatoire ici : ton Debian est derrière ta box (NAT), donc sans paquet régulier, le VPS perdrait le chemin de retour.

```bash
sudo systemctl enable --now wg-quick@wg0
```

### Vérifier le tunnel

```bash
# depuis le VPS
ping -c3 10.10.0.2
# depuis le Debian
ping -c3 10.10.0.1
```

Les deux doivent répondre. Si `wg show` affiche un `latest handshake` récent des deux côtés, le tunnel est bon.

---

## 4. DNS

```
Type: A
Nom:  vault.exemple.com
Valeur: VPS_IP_PUBLIQUE
```

```bash
dig +short vault.exemple.com   # doit renvoyer l'IP du VPS
```

---

## 5. TLS + reverse proxy — sur le Debian, pas sur le VPS

C'est la différence clé avec un montage classique : Caddy tourne **chez toi**, pas sur le VPS. Le VPS n'a jamais la clé privée TLS ni le trafic déchiffré.

```bash
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https curl
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
  | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
  | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt update
sudo apt install -y caddy
```

`/etc/caddy/Caddyfile` :

```caddyfile
vault.exemple.com {
    reverse_proxy 127.0.0.1:58951
}
```

```bash
sudo systemctl reload caddy
```

Caddy écoute en local sur `:80`/`:443`. Les paquets que lui envoie le VPS (via DNAT + tunnel) arrivent sur ces mêmes ports normalement — Caddy ne sait même pas qu'un VPS existe entre lui et internet. La validation Let's Encrypt (HTTP-01 sur le port 80) fonctionne exactement pareil puisque le port 80 est bien forwardé.

> Si `ufw` est actif sur le Debian, assure-toi qu'il autorise 80/443 en entrée (`sudo ufw allow 80,443/tcp`), sinon Caddy recevra bien les paquets du tunnel mais le firewall local les bloquera avant.

---

## 6. Config xVault

Le conteneur xVault n'a besoin d'écouter qu'en local, puisque c'est Caddy (sur le même hôte) qui lui parle :

`docker-compose.yml` :

```yaml
    ports:
      - "127.0.0.1:58951:58951"
```

`config.json` (celui monté dans le conteneur) :

```json
{
  "SERVER_HOST": "0.0.0.0",
  "SERVER_PORT": 58951,
  "SERVER_URL": "https://vault.exemple.com",
  "ALLOW_REGISTRATION": false
}
```

```bash
docker compose up -d
```

---

## 7. Résultat

- `https://vault.exemple.com` → résout vers l'IP du VPS.
- Le VPS relaie les octets bruts (il ne voit que du TLS chiffré, aucune clé, aucun déchiffrement) vers ton Debian via le tunnel.
- Ton Debian termine le TLS, sert xVault.
- Ton IP maison n'apparaît **jamais** : ni en DNS, ni dans le certificat (délivré pour le domaine, validé via le VPS), ni dans aucune réponse réseau vue depuis internet.

---

## Dépannage

| Symptôme | Piste |
| --- | --- |
| `wg show` : pas de `latest handshake` | Clés publiques mal croisées, ou port UDP 51820 bloqué par le firewall du VPS. |
| Le ping entre `10.10.0.1` et `10.10.0.2` ne passe pas | Vérifie `AllowedIPs` des deux côtés, et que `wg-quick@wg0` est bien actif (`systemctl status wg-quick@wg0`). |
| Le site ne répond pas du tout depuis internet | `sysctl net.ipv4.ip_forward` doit valoir `1` sur le VPS ; vérifie `sudo iptables -t nat -L -n -v` pour confirmer que les règles DNAT sont bien présentes (elles disparaissent si le tunnel est down, puisqu'elles sont dans PostUp/PostDown). |
| Ça répond mais sans réponse retour (timeout côté client) | Règle `MASQUERADE` manquante ou mal appliquée — sans elle, le Debian essaie de répondre directement au client, ce qui échoue. |
| Caddy ne décroche pas de certificat | Le port 80 doit être joignable *de bout en bout* (VPS → tunnel → Debian → Caddy) pour la validation ACME. Teste depuis l'extérieur : `curl -I http://vault.exemple.com`. |
| `iptables: command not found` sur un Debian récent | `sudo apt install iptables` (Debian 13 fournit la compatibilité nftables, mais le binaire `iptables` doit être installé explicitement). |
| Ça remarchait puis plus rien après un reboot du VPS | Vérifie que `wg-quick@wg0` est bien `enabled` (pas juste démarré une fois) : `sudo systemctl enable wg-quick@wg0`. |

Commandes de diagnostic utiles :

```bash
sudo wg show                          # état du tunnel, des deux côtés
sudo iptables -t nat -L -n -v         # règles DNAT/MASQUERADE actives sur le VPS
sudo journalctl -u caddy -f           # logs Caddy (côté Debian)
docker compose logs -f                # logs xVault
curl -I http://vault.exemple.com      # valide que le port 80 arrive jusqu'au Debian
```
