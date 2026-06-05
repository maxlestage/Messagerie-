//
//  App.tsx
//  Messagerie 🥦 — messagerie chiffrée bâtie sur brocolis 🥦
//

import React from 'react';
import { ActivityIndicator, View } from 'react-native';
import { NavigationContainer } from '@react-navigation/native';
import { createNativeStackNavigator } from '@react-navigation/native-stack';
import { SafeAreaProvider } from 'react-native-safe-area-context';
import { StatusBar } from 'expo-status-bar';

import { AppProvider, useApp } from './src/state/AppContext';
import { RootStackParamList } from './src/models/types';
import ConversationsScreen from './src/screens/ConversationsScreen';
import ChatScreen from './src/screens/ChatScreen';
import KeyScreen from './src/screens/KeyScreen';

const Stack = createNativeStackNavigator<RootStackParamList>();

const headerOptions = {
  headerStyle: { backgroundColor: '#4a9e4a' },
  headerTintColor: '#ffffff',
  headerTitleStyle: { fontWeight: '600' as const },
};

function RootNavigator() {
  const { loaded } = useApp();

  if (!loaded) {
    return (
      <View style={{ flex: 1, alignItems: 'center', justifyContent: 'center' }}>
        <ActivityIndicator color="#4a9e4a" />
      </View>
    );
  }

  return (
    <Stack.Navigator screenOptions={headerOptions}>
      <Stack.Screen
        name="Conversations"
        component={ConversationsScreen}
        options={{ title: 'Messagerie 🥦' }}
      />
      <Stack.Screen name="Chat" component={ChatScreen} />
      <Stack.Screen
        name="Key"
        component={KeyScreen}
        options={{ title: 'Clé de chiffrement', presentation: 'modal' }}
      />
    </Stack.Navigator>
  );
}

export default function App() {
  return (
    <SafeAreaProvider>
      <AppProvider>
        <NavigationContainer>
          <StatusBar style="light" />
          <RootNavigator />
        </NavigationContainer>
      </AppProvider>
    </SafeAreaProvider>
  );
}
