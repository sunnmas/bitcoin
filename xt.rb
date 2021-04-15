#https://bitaps.com/broadcast - отправить транзакцию в сеть
#https://habr.com/ru/post/319862/ - Bitcoin in a nutshell — Protocol
#https://bitcoin-script-debugger.visvirial.com/ - дебугер скриптов биткоин
#https://bitcoin.stackexchange.com/questions/32628/redeeming-a-raw-transaction-step-by-step-example-required - алгоритм формирования транзакции
require './keys.rb'

def little_endian(str)
        (0..(str.length-1)/2).map{|i|str[i*2,2]}.reverse.join
end
#1 000 Satoshi  =       0.00001000 BTC
#127 807 s = 0.00127807 btc

keys = Keys.new
keys.generate PRIVATE
dest_keys = Keys.new
dest_keys.generate PRIVATE

puts "КЛЮЧИ ОТ АДРЕСА С КОТОРОГО СПИСЫВАЕМ"
puts "ПРИВАТНЫЙ КЛЮЧ"
puts "  Шестнадцатеричная запись:     #{keys.priv hex: true}"
puts "ОТКРЫТЫЙ КЛЮЧ"
puts "  Несжатая запись:              #{keys.pub compressed: false}"
puts "  Сжатая запись:                #{keys.pub compressed: true}"
puts "АДРЕС:"
puts "  Сжатая запись:                #{keys.address b58: true}"
puts "  Распакованная запись:         #{keys.address}"
puts "================================================================"
puts "КЛЮЧИ ОТ АДРЕСА НА КОТОРЫЙ ПЕРЕСЫЛАЕМ"
puts "ПРИВАТНЫЙ КЛЮЧ"
puts "  Шестнадцатеричная запись:     #{dest_keys.priv hex: true}"
puts "ОТКРЫТЫЙ КЛЮЧ"
puts "  Несжатая запись:              #{dest_keys.pub compressed: false}"
puts "  Сжатая запись:                #{dest_keys.pub compressed: true}"
puts "АДРЕС:"
puts "  Сжатая запись:                #{dest_keys.address b58: true}"
puts "  Распакованная запись:         #{dest_keys.address}"

# Формируем транзакцию
version = '01000000' #версия 1
inputs_count = '01' #количество входов в транзакции
#id транзакции которая поступает на вход:
prev_tx_hash = '5b8be25912bb21bfe335b320a2c3144aa97c8f4d5961f125cd6f6070ffa711f8'
prev_tx_hash = little_endian prev_tx_hash
puts prev_tx_hash
prev_out_index = '00000000' #номер выхода, который передаем на вход
sequence = 'ffffffff' #just some constant
outputs_count = '01' #количество выходов
value = little_endian '000000000001eb6f' #количество сатошей для перевода (hex)
script_pub_key_len = '19' #длина разблокирующего скрипта
#блокирующая часть смарт контракта P2PKH (Pay-to-Public-Key Hash):
# Механизм проверки действительности транзакций, а заодно, и вся система передачи
# ценности от одного владельца другому в блокчейне платформы Биткоин опирается на
# два типа сценариев: блокирующий сценарий и разблокирующий.
# Блокирующий скрипт воплощает налагаемое на выход транзакции обременение.
# Здесь определяются условия, выполнение которых откроет в будущем доступ к средствам,
# замороженным на выходе транзакции. Исторически сложилось так, что сценарий
# блокировки назывался scriptPubKey (сценарий открытого ключа).
# В большинстве случаев этот скрипт действительно хранил открытый ключ или биткоин-адрес.
#OP_DUP OP_HASH160 DESTINATION_ADDR OP_EQUALVERIFY OP_CHECKSIG
# OP_DUP: Duplicates the top stack item. (0x76)
# OP_HASH160: The input is hashed twice: first with SHA-256 and then with RIPEMD-160. (0xa9)
# OP_EQUALVERIFY: Same as OP_EQUAL, but runs OP_VERIFY afterward. (0x88)
# OP_CHECKSIG: The entire transaction's outputs, inputs, and script
#(from the most recently-executed OP_CODESEPARATOR to the end) are hashed.
#The signature used by OP_CHECKSIG must be a valid signature for this hash
#and public key. If it is, 1 is returned, 0 otherwise. (ac)
# здесь 0x14: OP_PUSHBYTES[20] поместить в буфер 160 бит (20 байт)
script_pub_key = '76a914'+dest_keys.hash160_pub+'88ac'
lock_time = '00000000' #количество времени для блокировки транзакции
hash_code_type = '01000000' #тип подписи - подписываем все входы и выходы

#Составляем предварительную транзакцию для подписи
tx = ''
tx << version << inputs_count << prev_tx_hash
tx << prev_out_index << script_pub_key_len << script_pub_key
tx << sequence << outputs_count << value << script_pub_key_len
tx << script_pub_key << lock_time << hash_code_type
puts "hash160_pub_dest: #{dest_keys.hash160_pub}"
puts "hash160_pub: #{keys.hash160_pub}"
puts "блокирующий скрипт: #{script_pub_key}"
puts "unsigned tx: #{tx}"

#От получившейся транзакции берем двойной хеш SHA256
tx_hash = Digest::SHA256.hexdigest [tx].pack('H*')
tx_hash = Digest::SHA256.hexdigest [tx_hash].pack('H*')

#Подписываем получившийся двойной хеш и представляем в формате DER -
#это и будет подпись для подтверждения владения входом транзакции,
#после чего к подписи добавляем 01 в конец
puts "tx_hash: #{tx_hash}"
group = ECDSA::Group::Secp256k1
signature = nil
while signature.nil?
  temp_key = 1 + SecureRandom.random_number(group.order - 1)
  signature = ECDSA.sign(group, keys.priv(hex: true).to_i(16), tx_hash, temp_key)
end
puts 'signature: '
puts '  r: %#x' % signature.r

# Чтобы избежать ошибки: Non-canonical signature: S value is unnecessarily high
N = 115792089237316195423570985008687907852837564279074904382605163141518161494337
if N/2 < signature.s
        puts "warning s > N/2"
        S = N - signature.s
else
        puts "s <= N/2"
        S = signature.s
end
puts '  s: %#x' % S

asn1 = OpenSSL::ASN1::Sequence.new [
          OpenSSL::ASN1::Integer.new(signature.r),
          OpenSSL::ASN1::Integer.new(S),
        ]
signature_der_string = asn1.to_der
signature_der_string = signature_der_string.unpack('H*')[0]+'01'

# signature_der_string = ECDSA::Format::SignatureDerString.encode(signature).unpack('H*')[0]+'01'
puts "sig DER: #{signature_der_string}"

#Проверка подписи на валидность.
# Берем исходное подписанное сообщение, публичный ключ и саму подпись и выясняем,
# было ли это сообщение подписано полученной подписью с помощью закрытого ключа,
# которому в соответствие поставлен данный открытый ключ
valid = ECDSA.valid_signature?(keys.pub(as_point: true), tx_hash, signature)
puts "signature valid: #{valid}"

# Каждый из скриптов выполняется отдельно, по очереди, а полученный
# после выполнения первого скрипта результат передается через стек.
# Рассмотрим подробнее каким образом это реализуется.

# Сначала выполняется разблокирующий скрипт. Если он выполнился без ошибок
# (например, не осталось лишних операторов), основной (не альтернативный) стек копируется.
# Затем запускается на исполнение блокирующий скрипт. Если результат выполнения блокирующего
# скрипта с ранее скопированным из стека результатом разблокирующего скрипта дает
# значение "TRUE", то данный вход транзакции признается действительным
# (в случае получения такого же результата проверок для остальных входов,
# транзакция считается полностью готовой (валидной) к включению в блокчейн).
# Т.е., разблокирующий скрипт смог полностью удовлетворить условиям обременения,
# закодированным в блокирующем скрипте и, следовательно, данный вход успешно
# подтвердил полномочия на трату конкретного неизрасходованного выхода. Если же в
# результате выполнения объединенного сценария получен иной результат (не "TRUE"),
# тогда вход признается недействительным, как не удовлетворившим условия доступа к
# средствам, закодированные в соответствующем нерастраченном выходе. Поскольку
# нерастраченный выход вместе с остальными частями транзакции уже записан в блокчейн
# (т.е., никогда не меняется), никакие недействительные (неудачные, или злонамеренные)
# попытки израсходовать его по ссылке из новой транзакции никак не могут на него повлиять.
# Только действительная транзакция, удовлетворяющая условиям ограничения, изменит состояние
# нерастраченного выхода на "растраченный" и вызовет его удаление из пула доступных
# (нерастраченных) выходов.
#Составляем разблокирующую часть смарт контракта:
len = (signature_der_string.length/2).to_s(16)
pub = keys.pub(compressed: true).downcase
script_sig = len
script_sig << signature_der_string
script_sig << (pub.length/2).to_s(16)+pub
script_sig_len = (script_sig.length/2).to_s(16)
puts "разблокирующий скрипт: "
puts '---------------'
puts (signature_der_string.length/2).to_s(16) + "\\"
puts signature_der_string + "\\"
puts (pub.length/2).to_s(16) + "\\"
puts pub
puts '---------------'





#Получаем подписанную готовую транзакцию
tx = ''
tx << version << inputs_count << prev_tx_hash
tx << prev_out_index << script_sig_len << script_sig
tx << sequence << outputs_count << value << script_pub_key_len
tx << script_pub_key << lock_time

puts "signed tx: #{tx}"

File.open("10101", 'wb'){|f| f.write([tx].pack('H*')) }