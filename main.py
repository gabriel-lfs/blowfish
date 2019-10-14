from Crypto import Random
from Crypto.Cipher import Blowfish
from Crypto.Cipher.Blowfish import MODE_ECB, MODE_CBC

block_size = Blowfish.block_size


def pad(plain_text):

    number_of_bytes_to_pad = block_size - len(plain_text) % block_size
    ascii_string = chr(number_of_bytes_to_pad)
    padding_str = number_of_bytes_to_pad * ascii_string
    padded_plain_text =  plain_text + padding_str
    return padded_plain_text

def unpad(string) -> bytes:
    return string[0:-ord(string[-1])]

def encrypt_decrypt(blowfish, text, question_number):
    try:
        encrypted = blowfish.encrypt(pad(text))
    except ValueError:
        encrypted = "Não foi possivel criptografar"
    
    try:
        decrypted = blowfish.decrypt(encrypted)
        decrypted = decrypted.decode()
    except ValueError:
        decrypted = "Não foi possível descriptografar"

    print(f'Questao {question_number} \n')
    print(f'Texto criptografado: {encrypted.hex()}')
    print(f'Tamanho da chave: {len(encrypted)}')
    print(f'Texto descriptografado: {unpad(decrypted)}\n')


blowfish_ECB = Blowfish.new(key=bytes("ABCDE", encoding="utf-8"), mode=MODE_ECB)

encrypt_decrypt(blowfish_ECB, "FURB", 1)

encrypt_decrypt(blowfish_ECB, "COMPUTADOR", 2)
print("Por que o texto cifrado tem tal tamanho?\nResposta: Por causa do tamanho do bloco a chave deve ser multiplo de 8")

encrypt_decrypt(blowfish_ECB, "SABONETE", 3)
print("Por que o texto cifrado tem tal tamanho?\nResposta: Pois embora a palavra tenha exatamente o tamanho de um bloco, ainda é necessário dos caracteres para a descriptografia")

encrypt_decrypt(blowfish_ECB, "SABONETESABONETESABONETE", 4)
print(
    "Avalie o conteúdo do texto cifrado. Que conclusão é possível obter a partir do texto cifrado e do texto simples?\n",
    "Resposta: O conteúdo é preenchido com caracteres repetidos"
)
try:
    print("Questão 5\n")
    blowfish_CBC = Blowfish.new(bytes("ABCDE", encoding="utf-8"), MODE_CBC)
    encrypt_decrypt(blowfish_CBC, "FURB", 5)
except ValueError:
    print("Não é possivel inicializar sem um vetor de incialização")

blowfish_CBC = Blowfish.new(bytes("ABCDE", encoding="utf-8"), MODE_CBC, bytes(bytearray([1, 1, 2, 2, 3, 3, 4, 4])))
encrypt_decrypt(blowfish_CBC, "FURB", 6)