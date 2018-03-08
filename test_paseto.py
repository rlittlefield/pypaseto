import pytest
import paseto

sym_key = bytes.fromhex('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f')
null_key = b'\0'*32
full_key = b'\xff'*32
nonce = b'\0'*24
nonce2 = bytes.fromhex('45742c976d684ff84ebdc0de59809a97cda2f64c84fda19b')


@pytest.mark.parametrize("token", [
    {
        'raw': b'v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNUtKpdy5KXjKfpSKrOlqQvQ',
        'message': b'',
        'key': null_key,
        'footer': b'',
        'nonce': nonce
    },
    {
        'raw': b'v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNSOvpveyCsjPYfe9mtiJDVg',
        'message': b'',
        'key': full_key,
        'footer': b'',
        'nonce': nonce
    },
    {
        'raw': b'v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNkIWACdHuLiJiW16f2GuGYA',
        'message': b'',
        'key': sym_key,
        'footer': b'',
        'nonce': nonce
    },
    {
        'raw': b'v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNfzz6yGkE4ZxojJAJwKLfvg.Q3VvbiBBbHBpbnVz',
        'message': b'',
        'key': null_key,
        'footer': b'Cuon Alpinus',
        'nonce': nonce
    },
    {
        'raw': b'v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNJbTJxAGtEg4ZMXY9g2LSoQ.Q3VvbiBBbHBpbnVz',
        'message': b'',
        'key': full_key,
        'footer': b'Cuon Alpinus',
        'nonce': nonce
    },
    {
        'raw': b'v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNreCcZAS0iGVlzdHjTf2ilg.Q3VvbiBBbHBpbnVz',
        'message': b'',
        'key': sym_key,
        'footer': b'Cuon Alpinus',
        'nonce': nonce
    },
    {
        'raw': b'v2.local.BEsKs5AolRYDb_O-bO-lwHWUextpShFSvu6cB-KuR4wR9uDMjd45cPiOF0zxb7rrtOB5tRcS7dWsFwY4ONEuL5sWeunqHC9jxU0',
        'message': b'Love is stronger than hate or fear',
        'key': null_key,
        'footer': b'',
        'nonce': nonce
    },
    {
        'raw': b'v2.local.BEsKs5AolRYDb_O-bO-lwHWUextpShFSjvSia2-chHyMi4LtHA8yFr1V7iZmKBWqzg5geEyNAAaD6xSEfxoET1xXqahe1jqmmPw',
        'message': b'Love is stronger than hate or fear',
        'key': full_key,
        'footer': b'',
        'nonce': nonce
    },
    {
        'raw': b'v2.local.BEsKs5AolRYDb_O-bO-lwHWUextpShFSXlvv8MsrNZs3vTSnGQG4qRM9ezDl880jFwknSA6JARj2qKhDHnlSHx1GSCizfcF019U',
        'message': b'Love is stronger than hate or fear',
        'key': sym_key,
        'footer': b'',
        'nonce': nonce
    },
    {
        'raw': b'v2.local.FGVEQLywggpvH0AzKtLXz0QRmGYuC6yvbcqXgWxM3vJGrJ9kWqquP61Xl7bz4ZEqN5XwH7xyzV0QqPIo0k52q5sWxUQ4LMBFFso.Q3VvbiBBbHBpbnVz',
        'message': b'Love is stronger than hate or fear',
        'key': null_key,
        'footer': b'Cuon Alpinus',
        'nonce': nonce2
    },
    {
        'raw': b'v2.local.FGVEQLywggpvH0AzKtLXz0QRmGYuC6yvZMW3MgUMFplQXsxcNlg2RX8LzFxAqj4qa2FwgrUdH4vYAXtCFrlGiLnk-cHHOWSUSaw.Q3VvbiBBbHBpbnVz',
        'message': b'Love is stronger than hate or fear',
        'key': full_key,
        'footer': b'Cuon Alpinus',
        'nonce': nonce2
    },
    {
        'raw': b'v2.local.FGVEQLywggpvH0AzKtLXz0QRmGYuC6yvl05z9GIX0cnol6UK94cfV77AXnShlUcNgpDR12FrQiurS8jxBRmvoIKmeMWC5wY9Y6w.Q3VvbiBBbHBpbnVz',
        'message': b'Love is stronger than hate or fear',
        'key': sym_key,
        'footer': b'Cuon Alpinus',
        'nonce': nonce2
    }
])
def test_encrypt(token):
    output_token = paseto.PasetoV2.encrypt(
        plaintext=token['message'],
        key=token['key'],
        footer=token['footer'],
        nonce_for_unit_testing=token['nonce']
    )
    assert output_token == token['raw']

    decrypted = paseto.PasetoV2.decrypt(
        token=token['raw'],
        key=token['key'],
    )
    assert decrypted['message'] == token['message']
    if decrypted['footer']:
        assert decrypted['footer']== token['footer']
