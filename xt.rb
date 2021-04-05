require './keys.rb'

def little_endian(str)
	(0..(str.length-1)/2).map{|i|str[i*2,2]}.reverse.join
end

keys = Keys.new
keys.generate PRIVATE_INFORMATION
dest_keys = Keys.new
dest_keys.generate PRIVATE_INFORMATION

puts "КЛЮЧИ ОТ АДРЕСА С КОТОРОГО СПИСЫВАЕМ"
puts "ПРИВАТНЫЙ КЛЮЧ"
puts "	Шестнадцатеричная запись:     #{keys.priv}"
puts "ОТКРЫТЫЙ КЛЮЧ"
puts "	Несжатая запись:              #{keys.pub false}"
puts "	Сжатая запись:                #{keys.pub true}"
puts "АДРЕС:"
puts "	Сжатая запись:                #{keys.address false}"
puts "	Распакованная запись:         #{keys.address true}"
puts "================================================================"
puts "КЛЮЧИ ОТ АДРЕСА НА КОТОРЫЙ ПЕРЕСЫЛАЕМ"
puts "ПРИВАТНЫЙ КЛЮЧ"
puts "	Шестнадцатеричная запись:     #{dest_keys.priv}"
puts "ОТКРЫТЫЙ КЛЮЧ"
puts "	Несжатая запись:              #{dest_keys.pub false}"
puts "	Сжатая запись:                #{dest_keys.pub true}"
puts "АДРЕС:"
puts "	Сжатая запись:                #{dest_keys.address false}"
puts "	Распакованная запись:         #{dest_keys.address true}"

# Формируем транзакцию
version = '01000000' #версия 1
inputs_count = '01' #количество входов в транзакции
#id транзакции которая поступает на вход:
prev_tx_hash = '5b8be25912bb21bfe335b320a2c3144aa97c8f4d5961f125cd6f6070ffa711f8'
prev_tx_hash = little_endian prev_tx_hash
puts prev_tx_hash
prev_out_index = '00000000' #номер выхода, который передаем на вход
sequence = 'ffffffff' #номер выхода, который передаем на вход
outputs_count = '01' #количество выходов
value = little_endian '0000001000000000' #количество сатошей для перевода
script_pub_key_len = '19' #длина разблокирующего скрипта
#разблокировочная часть смарт контракта:
#OP_DUP HASH160 DESTINATION_ADDR OP_EQUALVERIFY OP_CHECKSIG
script_pub_key = '76a914'+dest_keys.hash160_pub+'88ac'
lock_time = '00000000' #количество времени для блокировки транзакции
hash_code_type = '01000000' #тип подписи - подписываем все входы и выходы

#Составляем предварительную транзакцию для подписи
tx = ''
tx << version << inputs_count << prev_tx_hash
tx << prev_out_index << script_pub_key_len << script_pub_key
tx << sequence << outputs_count << value << script_pub_key_len
tx << script_pub_key << lock_time << hash_code_type
puts "hash160_pub: #{dest_keys.hash160_pub}"
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
  signature = ECDSA.sign(group, keys.priv.to_i(16), tx_hash, temp_key)
end
puts 'signature: '
puts '  r: %#x' % signature.r
puts '  s: %#x' % signature.s

signature_der_string = ECDSA::Format::SignatureDerString.encode(signature).unpack('H*')[0]+'01'
puts "sig DER: #{signature_der_string}"

#Проверка подписи на валидность.
# Берем исходное подписанное сообщение, публичный ключ и саму подпись и выясняем,
# было ли это сообщение подписано полученной подписью с помощью закрытого ключа, 
# которому в соответствие поставлен данный открытый ключ
valid = ECDSA.valid_signature?(keys.pub_as_point, tx_hash, signature)
puts "signature valid: #{valid}"

#Составляем блокирующую часть смарт контракта:
len = (signature_der_string.length/2).to_s(16)
pub = keys.pub(false)
script_sig = len
script_sig << signature_der_string
script_sig << (pub.length/2).to_s(16)+pub
script_sig_len = (script_sig.length/2).to_s(16)

#Получаем подписанную готовую транзакцию
tx = ''
tx << version << inputs_count << prev_tx_hash
tx << prev_out_index << script_sig_len << script_sig
tx << sequence << outputs_count << value << script_pub_key_len
tx << script_pub_key << lock_time

puts "signed tx: #{tx}"

File.open("10101", 'wb'){|f| f.write([tx].pack('H*')) }