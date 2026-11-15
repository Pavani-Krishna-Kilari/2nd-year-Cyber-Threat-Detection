"""
Long Short-Term Memory (LSTM) Network for Event Profiles.

Methodological Justification:
  In our Phase 3 implementation, an event profile's 8 basepoint cosine similarities are
  concurrent coordinates in 5-dimensional event space, NOT a sequence of time steps.
  Therefore, the 8 basepoint dimensions are never unrolled into 8 fake time steps.
  
  Instead, the temporal sequence represents the progression of complete 8-dimensional
  event profiles across sliding windows for a communicating host-pair over time:
    S_(src, dst) = [p(t - T + 1), ..., p(t - 1), p(t)] in R^(T x 8)
  
  For single-window / stateless evaluation (e.g. ad-hoc triage or cold start),
  time_steps = 1, where the full 8-dimensional profile vector represents the initial
  concurrency state at t=0, processed without distorting feature semantics.
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


def build_lstm(input_dim: int = 8, time_steps: int = 1, learning_rate: float = 0.001):
    """
    Builds and compiles a Bidirectional LSTM model for threat detection.
    
    If time_steps == 1 (standard event-set profile row):
      Input shape (input_dim,) is reshaped to (1, input_dim), representing
      1 time step with 8 concurrent basepoint dimensions.
    If time_steps > 1 (temporal multi-window sequence):
      Input shape is (time_steps, input_dim).
    """
    if not HAS_KERAS:
        raise ImportError("TensorFlow / Keras is not installed or available.")

    if time_steps == 1:
        inputs = layers.Input(shape=(input_dim,), name="profile_input")
        x = layers.Reshape((1, input_dim), name="reshape_to_sequence")(inputs)
    else:
        inputs = layers.Input(shape=(time_steps, input_dim), name="profile_sequence_input")
        x = inputs

    x = layers.Bidirectional(
        layers.LSTM(32, return_sequences=False, kernel_regularizer=regularizers.l2(1e-4)),
        name="bidirectional_lstm"
    )(x)
    x = layers.BatchNormalization(name="batch_norm")(x)
    x = layers.Dense(16, activation="relu", name="dense_1")(x)
    x = layers.Dropout(0.2, name="dropout")(x)
    outputs = layers.Dense(1, activation="sigmoid", name="threat_probability")(x)

    model = models.Model(inputs=inputs, outputs=outputs, name="LSTM_EventProfile")
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
