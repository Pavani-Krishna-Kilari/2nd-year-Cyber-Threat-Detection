"""
1D Convolutional Neural Network (1D-CNN) for Event Profiles.

Input: 8 basepoint cosine similarities reshaped to (8, 1).
Justification:
  The 8 basepoints represent an ordered spectrum of prototype security behaviors.
  1D convolutions with small kernel sizes (k=3) slide across adjacent basepoints to
  detect localized co-occurrence patterns (e.g. combined rate and SYN surges).
  Global pooling condenses these local sub-signatures into an invariant feature map.
Output: Threat probability in [0.0, 1.0] (Sigmoid activation).
"""

try:
    import keras
    from keras import layers, models, regularizers
    HAS_KERAS = True
except ImportError:
    try:
        from tensorflow import keras
        from tensorflow.keras import layers, models, regularizers
        HAS_KERAS = True
    except ImportError:
        keras = None
        layers = None
        models = None
        regularizers = None
        HAS_KERAS = False


def build_cnn(input_dim: int = 8, learning_rate: float = 0.001):
    """
    Builds and compiles a 1D-CNN model for binary threat detection.

    Architecture:
      Input (8,) -> Reshape((8, 1))
                 -> Conv1D(32, k=3, same, ReLU) -> BatchNorm
                 -> Conv1D(64, k=3, same, ReLU)
                 -> GlobalMaxPooling1D
                 -> Dense(32, ReLU) -> Dropout(0.2)
                 -> Dense(1, Sigmoid)
    """
    if not HAS_KERAS:
        raise ImportError("TensorFlow / Keras is not installed or available.")

    inputs = layers.Input(shape=(input_dim,), name="profile_input")
    x = layers.Reshape((input_dim, 1), name="reshape_to_1d_channel")(inputs)

    x = layers.Conv1D(
        32, kernel_size=3, padding="same", activation="relu",
        kernel_regularizer=regularizers.l2(1e-4), name="conv1d_1"
    )(x)
    x = layers.BatchNormalization(name="batch_norm_1")(x)

    x = layers.Conv1D(
        64, kernel_size=3, padding="same", activation="relu",
        kernel_regularizer=regularizers.l2(1e-4), name="conv1d_2"
    )(x)
    x = layers.GlobalMaxPooling1D(name="global_max_pool")(x)

    x = layers.Dense(32, activation="relu", name="dense_proj")(x)
    x = layers.Dropout(0.2, name="dropout")(x)

    outputs = layers.Dense(1, activation="sigmoid", name="threat_probability")(x)

    model = models.Model(inputs=inputs, outputs=outputs, name="CNN1D_EventProfile")
    optimizer = keras.optimizers.Adam(learning_rate=learning_rate)
    model.compile(
        optimizer=optimizer,
        loss="binary_crossentropy",
        metrics=[
            "accuracy",
            keras.metrics.Precision(name="precision"),
            keras.metrics.Recall(name="recall"),
            keras.metrics.AUC(name="pr_auc", curve="PR")
        ]
    )
    return model
