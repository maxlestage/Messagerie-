//
//  MessageBubble.tsx
//  Messagerie 🥦
//

import React, { useMemo } from 'react';
import { StyleSheet, Text, View } from 'react-native';

import { Message } from '../models/types';
import { containsToken, decryptTokens } from '../crypto/brocolisCrypto';

interface Props {
  message: Message;
  keyBytes: Uint8Array | null;
  showRaw: boolean;
}

function formatTime(epochMs: number): string {
  const d = new Date(epochMs);
  const hh = d.getHours().toString().padStart(2, '0');
  const mm = d.getMinutes().toString().padStart(2, '0');
  return `${hh}:${mm}`;
}

export default function MessageBubble({ message, keyBytes, showRaw }: Props) {
  const isMine = message.sender === 'me';
  const isEncrypted = containsToken(message.wireText);

  const { display, locked } = useMemo(() => {
    if (showRaw) {
      return { display: message.wireText, locked: isEncrypted };
    }
    if (keyBytes) {
      const { text, count } = decryptTokens(message.wireText, keyBytes);
      return { display: text, locked: isEncrypted && count === 0 };
    }
    // Pas de clé : on montre le texte « sur le fil ».
    return { display: message.wireText, locked: isEncrypted };
  }, [message.wireText, keyBytes, showRaw, isEncrypted]);

  return (
    <View style={[styles.row, isMine ? styles.rowMine : styles.rowTheirs]}>
      <View
        style={[
          styles.bubble,
          isMine ? styles.bubbleMine : styles.bubbleTheirs,
        ]}
      >
        <Text
          style={[
            showRaw ? styles.rawText : styles.text,
            isMine ? styles.textMine : styles.textTheirs,
          ]}
          selectable
        >
          {display}
        </Text>
        <View style={styles.metaRow}>
          {isEncrypted ? (
            <Text style={[styles.meta, isMine ? styles.metaMine : styles.metaTheirs]}>
              {locked ? '🔒' : '🔓'}{' '}
            </Text>
          ) : null}
          <Text style={[styles.meta, isMine ? styles.metaMine : styles.metaTheirs]}>
            {formatTime(message.date)}
          </Text>
        </View>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  row: {
    flexDirection: 'row',
    marginVertical: 4,
  },
  rowMine: { justifyContent: 'flex-end' },
  rowTheirs: { justifyContent: 'flex-start' },
  bubble: {
    maxWidth: '82%',
    paddingHorizontal: 12,
    paddingVertical: 8,
    borderRadius: 16,
  },
  bubbleMine: { backgroundColor: '#4a9e4a' },
  bubbleTheirs: { backgroundColor: '#e6e6e6' },
  text: { fontSize: 16 },
  rawText: { fontSize: 13, fontFamily: 'Courier' },
  textMine: { color: '#ffffff' },
  textTheirs: { color: '#111111' },
  metaRow: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'flex-end',
    marginTop: 2,
  },
  meta: { fontSize: 11 },
  metaMine: { color: 'rgba(255,255,255,0.85)' },
  metaTheirs: { color: '#666666' },
});
