#include <string.h>
#include <iostream>
#include <openssl/hmac.h>

#include "messageDef.h"

class Hash {
    private:
        std::string key;
        std::string hashed_msg;
    public:
        // Prende come input la chiave del client o del server
        Hash(std::string);
        // Ritorna hamc calcolato
        std::string getHmac();
        void setHmac(std::string);
        // Prende in input il #seq e il messaggio. Calcola Hmac lo salva nella variabile privata hashed_msg
        void computeHash(std::string, uint32_t);
        // Prende in input il #seq aspettato e il cx
        bool verifyHamc(std::string, uint32_t);    
};