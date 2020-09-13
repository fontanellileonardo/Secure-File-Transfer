#include "hash.h"

Hash::Hash(std::string key) {
    this->key = key;
    this->hashed_msg = "";
}

// Ritorna hamc calcolato
std::string Hash::getHmac() {
    return this->hashed_msg;
}

void Hash::setHmac(std::string hashed_msg) {
    this->hashed_msg = hashed_msg;
}

// Prende in input il #seq e il messaggio. Calcola Hmac lo salva nella variabile privata hashed_msg
void Hash::computeHash(std::string msg, uint32_t seq_num) {
    unsigned char* hash_buf = new unsigned char[EVP_MD_size(EVP_sha256())]; // 32 byte
    // dimensione del digest
    unsigned int hash_size;

    std::string final_msg = std::to_string(seq_num) + msg;
    std::cout << "Seq num è " << std::to_string(seq_num) << ", msg è " << msg << std::endl;
    std::cout << "Messaggio con seq num è:"<<final_msg<<std::endl;

    // Creo il contesto
    HMAC_CTX* ctx = HMAC_CTX_new();
    if(!ctx) {
        std::cout << "Errore nella creazione del contesto del HMAC" << std::endl;
        exit(1);
    }

    //Argomenti sono in successione: contesto, chiave, grandezza della chiave, hash function da utilizzare
    if(!HMAC_Init_ex(ctx, (unsigned char*)this->key.c_str(), HASH_KEY_LENGTH, EVP_sha256(), NULL)) {
        std::cout << "Errore nella init di HMAC" << std::endl;
        exit(1);
    }
    if(!HMAC_Update(ctx, (unsigned char*)final_msg.c_str(), final_msg.size())) {
        std::cout << "Errore nella update di HMAC" << std::endl;
        exit(1);
    }
    if(!HMAC_Final(ctx, hash_buf, &hash_size)) {
        std::cout << "Errore nella final di HMAC" << std::endl;
        exit(1);
    }

    // Salvo il digest calcolato in hashed_msg
    this->hashed_msg.assign((char*)hash_buf, hash_size);
    std::cout << "digest calcolato è: " << this->hashed_msg << std::endl;

    //Delete context
    HMAC_CTX_free(ctx);
    delete[] hash_buf;
}

// Prende in input il #seq aspettato e il cx
bool Hash::verifyHamc(std::string ciphertext, uint32_t seq_num) {
    // in this->hashed_msg c'è il digest ricevuto
    std::string hmac_rcvd = this->hashed_msg;
    
    // calcolo il digest passando il #seq aspettato e il messaggio ricevuto
    this->computeHash(ciphertext, seq_num);

    // Verifico i due digest siano uguali
    if(CRYPTO_memcmp((unsigned char*)this->hashed_msg.c_str(), (unsigned char*)hmac_rcvd.c_str(), EVP_MD_size(EVP_sha256())) != 0) {
        std::cout << "Controllo sui digest è fallito!!" << std::endl;
        std::cout << "Il digest ricevuto è: " << hmac_rcvd << std::endl;
        std::cout << "Il digest calcolato è: " << this->hashed_msg << std::endl;
        return false;
    }
    return true;
}
/*
*   MAIN DI DEBUG
*/
/*
int main(int argc, char* argv[]){
    std::string key = "0123456789012345678901234567891";
   
    // sender
    Hash* h_to_send = new Hash(key);
    int32_t seq_num= 3;
    h_to_send->computeHash("Short Message", seq_num);

    // riceiver
    Hash* h_to_recv = new Hash(key);
    h_to_recv->setHmac(h_to_send->getHmac());
    bool res = h_to_recv->verifyHamc("Short Message", seq_num);
    std::cout << "Risultato della verify: " << res << std::endl;
    return 0;
}
*/