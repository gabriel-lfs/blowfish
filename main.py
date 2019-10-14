from Crypto import Random
from Crypto.Cipher import Blowfish
from Crypto.Cipher.Blowfish import MODE_ECB, MODE_CBC

block_size = Blowfish.block_size

"""
Questao 1 

Texto criptografado: b'\x7fG\x00\xaao_\xe0\x8b'
Texto criptografado Hexadecimal: 7f4700aa6f5fe08b
Tamanho da chave: 8

Questao 2 

Texto criptografado: b'\xf3G9\xabv4\xc4\xef\xe5\x0f\xf1\xb5T\x85er'
Texto criptografado Hexadecimal: f34739ab7634c4efe50ff1b554856572
Tamanho da chave: 16

Por que o texto cifrado tem tal tamanho?
Resposta: Por causa do tamanho do bloco a chave deve ser multiplo de 8
Questao 3 

Texto criptografado: b'\x84\x10\x91G&\x04\xb9j\xcd\xbc>/\xef\xa7;\xdd'
Texto criptografado Hexadecimal: 841091472604b96acdbc3e2fefa73bdd
Tamanho da chave: 16

Por que o texto cifrado tem tal tamanho?
Resposta: Pois embora a palavra tenha exatamente o tamanho de um bloco, ainda é necessário dos caracteres para a descriptografia
Questao 4 

Texto criptografado: b'\x84\x10\x91G&\x04\xb9j\x84\x10\x91G&\x04\xb9j\x84\x10\x91G&\x04\xb9j\xcd\xbc>/\xef\xa7;\xdd'
Texto criptografado Hexadecimal: 841091472604b96a841091472604b96a841091472604b96acdbc3e2fefa73bdd
Tamanho da chave: 32

Avalie o conteúdo do texto cifrado. Que conclusão é possível obter a partir do texto cifrado e do texto simples?
 Resposta: O conteúdo é preenchido com caracteres repetidos
Questão 5

Não é possivel inicializar sem um vetor de incialização
Questao 6 

Texto criptografado: b'\xcf\nu\xa3T\xfbbL'
Texto criptografado Hexadecimal: cf0a75a354fb624c
Tamanho da chave: 8

Questao 7 

Texto criptografado: b'\x8e\xe3\xb3\xa1\x9ehGT\xf0ob`\xaeb\x16X\xa8\x11\xbe\x88\xdf_h\xfd\xed\x8c\xb3@H*\x0b\x16'
Texto criptografado Hexadecimal: 8ee3b3a19e684754f06f6260ae621658a811be88df5f68fded8cb340482a0b16
Tamanho da chave: 32

Não é possível indentificar a repetição dos caracteres nesse como no da questão 4

Questao 8 

Texto criptografado: b'\x10\x98\x1f\xe3\x00\x9f\x1f\xe0\xabu\x92\x17\x9c6\x1c\xc7\xaf\x8e\xb3\x90\xb7\x9e\xbc\x8e\xd6\xa1\xf7\x1dC\xe1\xc0\xc4'
Texto criptografado Hexadecimal: 10981fe3009f1fe0ab7592179c361cc7af8eb390b79ebc8ed6a1f71d43e1c0c4
Tamanho da chave: 32

O texto é completamente diferente
Texto descriptografado: XT^ezSABONETESABONETE
Questao 9 

Texto criptografado: b'\x7fG\x00\xaao_\xe0\x8b'
Texto criptografado Hexadecimal: 7f4700aa6f5fe08b
Tamanho da chave: 8

Texto descriptografado: b'\x9dd\xf3\xa9\xfe\xf08G'
Os bytes que são descriptografados com essa chave não são legíveis
"""

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

    print(f'Questao {question_number} \n')
    print(f'Texto criptografado: {encrypted}')
    print(f'Texto criptografado Hexadecimal: {encrypted.hex()}')
    print(f'Tamanho da chave: {len(encrypted)}\n')

    return encrypted


blowfish_ECB = Blowfish.new(key=bytes("ABCDE", encoding="ascii"), mode=MODE_ECB)

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
    blowfish_CBC = Blowfish.new(bytes("ABCDE", encoding="ascii"), MODE_CBC)
    encrypt_decrypt(blowfish_CBC, "FURB", 5)
except ValueError:
    print("Não é possivel inicializar sem um vetor de incialização")

blowfish_CBC = Blowfish.new(bytes("ABCDE", encoding="ascii"), MODE_CBC, bytes(bytearray([1, 1, 2, 2, 3, 3, 4, 4])))
encrypt_decrypt(blowfish_CBC, "FURB", 6)

encrypt_decrypt(blowfish_CBC, "SABONETESABONETESABONETE", 7)
print("Não é possível indentificar a repetição dos caracteres nesse como no da questão 4\n")

blowfish_CBC = Blowfish.new(bytes("ABCDE", encoding="ascii"), MODE_CBC, bytes(bytearray([10, 20, 30, 40, 50, 60, 70, 80])))

encrypted_text = encrypt_decrypt(blowfish_CBC, "SABONETESABONETESABONETE", 8)
print("O texto é completamente diferente")

blowfish_CBC = Blowfish.new(bytes("ABCDE", encoding="ascii"), MODE_CBC, bytes(bytearray([1, 1, 2, 2, 3, 3, 4, 4])))
decrypted_text = blowfish_CBC.decrypt(encrypted_text)
print(f"Texto descriptografado: {decrypted_text.decode()}")

encrypted_text = encrypt_decrypt(blowfish_ECB, "FURB", 9)

blowfish_ECB = Blowfish.new(key=bytes("11111", encoding="ascii"), mode=MODE_ECB)

decrypted_text = blowfish_ECB.decrypt(encrypted_text)
print(f"Texto descriptografado: {decrypted_text}")
print(f"Os bytes que são descriptografados com essa chave não são legíveis")
